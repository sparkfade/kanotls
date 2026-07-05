# KanoTLS — 内部机制参考

本文档描述 KanoTLS 的内部架构、密码学设计和流量整形逻辑。先阅读主 README 获取概览。

---

## 1. 握手认证嵌入

### 1.1 Noise 在 ClientHello 字段中的封装

外层 TLS ClientHello 在 TLS 1.3 预期为随机的字段中承载完整的 `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` 初始握手载荷：

| ClientHello 字段　　　　　| 内容　　　　　　　　　　　　　　　　　 | 大小 | 编码方式　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| ---------------------------| ----------------------------------------| ------| --------------------------------------------------------------------------------------|
| `random[0..32]`　　　　　 | Noise initiator 临时 X25519 公钥 (`e`) | 32 B | 与 `derive_noise_e_mask(derived_psk, noise_tag)` 进行 XOR　　　　　　　　　　　　　　|
| `session_id[0..16]`　　　 | Noise PSK 认证的 AEAD tag　　　　　　　| 16 B | 直接复制 `psk_e[32..48]`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| `session_id[16..24]`　　　| 连接计数器　　　　　　　　　　　　　　 | 8 B　| 与 `derive_counter_mask(derived_psk, random)` 进行 XOR　　　　　　　　　　　　　　　 |
| `session_id[24..32]`　　　| 计数器认证 MAC　　　　　　　　　　　　 | 8 B　| `derive_counter_mac(psk, random, masked_counter, random[..16])`；字节 31 低 2 位清零 |
| `key_share` (扩展 0x0033) | 独立的 TLS 层 X25519 临时密钥　　　　　| 32 B | `rand::thread_rng().fill_bytes()` — 与 Noise 密钥无关　　　　　　　　　　　　　　　　|

映射是确定性的：给定相同的 PSK 和 Noise initiator 状态，产生的 ClientHello 字段相同。服务端通过应用相同的 XOR 掩码恢复 Noise 临时密钥，重建 48 字节的 Noise init 消息（32B `e` + 16B tag），并完成 `NoiseState::read_message()`。

### 1.2 为什么使用双 Key Share？

`key_share` 扩展包含每连接独立的新鲜随机 X25519 公钥。该密钥用于与参考（伪装）端点完成可见的 TLS 握手。它与 `random` 中的 Noise 密钥**密码学独立**。这防止被动观察者通过统计测试关联两个 32 字节字段——它们来自独立的熵源（`rand::thread_rng` vs `snow::Builder::build_initiator()`）。

### 1.3 计数器防重放

64 位计数器切分为：

```
counter = (session_id << 24) | sequence
```

- **session_id**（40 位）：每次客户端重启随机生成，隔离独立会话。
- **sequence**（24 位）：每个会话内严格单调，从 1 开始。

服务端使用每个会话命名空间的**64 位滑动窗口位图**（LRU 缓存，4096 条目）。比最高已见序号新的序列推进窗口；最多落后 63 的序列在位图中检查；更旧的序列被拒绝。同一序列号永不接受两次。

独立的**临时密钥重放缓存**（LRU，65536 条目，600 秒 TTL）通过对恢复的 Noise 临时公钥建立索引来捕获完整的 ClientHello 重放。

---

## 2. 伪装 Profile 系统

### 2.1 Profile 结构

`CamouflageProfile` 记录了参考端点的可见 TLS 1.3 握手形态：

| 字段 | 说明 |
|---|---|
| `server_records` | 所有可见握手记录（ServerHello、Certificate、CCS 等）的原始字节 |
| `prefix_app_data_sizes` | 因太小而无法承载 Noise 载荷的早期 0x17 记录的线速大小 |
| `app_data_sizes` | 参考端点所有采样的 0x17 记录的线速大小 |
| `first_app_data_delay_ms` | ServerHello 完成到首个 0x17 记录之间的毫秒数 |
| `early_app_data_gap_ms` | 连续 0x17 记录间的时间间隔 |
| `has_ccs` | 参考端点是否发送了 CCS 记录 |

### 2.2 启动健康检查

服务端启动时，`validate_camouflage_endpoint()` 向参考端点发送 4 次新鲜 rustls 生成的 ClientHello。每次 flight 经指纹化（random/session_id/key_share 置零，padding 扩展规范化）后，按 per-指纹 key 和指纹族 baseline key（指纹哈希的前 8 个 hex 字符）进行缓存。

### 2.3 逐连接回放

客户端连接时：

1. 通过 `stable_client_hello_fingerprint()` 对 ClientHello 进行指纹化。
2. 服务端查找最佳缓存 profile（偏好完整 profile：rank 3 = 同时具有 server_records 和 app_data_sizes）。
3. 若没有完整缓存 profile，`fetch_camouflage_flight()` 向参考端点执行实时获取（含 refresh-gate 去重）。
4. `establish_synthetic_camouflage_tunnel()`：
   - 将客户端的 `session_id` 回显到缓存的 ServerHello 中。
   - 用新鲜随机字节替换 ServerHello 的 `random`（若存在降级哨兵则保留）。
   - 发送所有可见握手记录。
   - 发送前缀 0x17 记录（太小而无法承载 Noise 载荷），从 `ENTROPY_POOL`（8 MiB 的 `rand::thread_rng()` 字节）填充。
   - 发送封装在 0x17 记录中的 Noise 应答（大小匹配缓存的首个 app_data 大小，Noise 服务端公钥 XOR 掩码在前 32 字节中）。
   - 发送幽灵 0x17 记录（按缓存大小），每条记录在填充熵池数据前，先写入 16 字节的伪造会话票据结构头部以降低熵指纹。

### 2.4 后台刷新

每个 (host, port) 对的守护进程每 300–3000 秒（随机化）使用与探测相同的 ClientHello 指纹刷新 profile。

---

## 3. 主动流量整形

### 3.1 设计缘由

v1.0 原始双模分布（§3.1–3.4）被动地在 `BLOCK_DATA_CAPACITY`（16382）边界上切分应用载荷，并以概率性尾部填充（80/20 抖动）包裹余量。这导致内部 TLS 明文尺寸被直接映射至外部线速记录尺寸，暴露结构指纹（例如 5000 字节的证书会生成 16382 + 16382 + 1236 = 三条记录，其尺寸对被动观察者泄露内部握手形态）。v1.1 引入**自上而下的主动 TrafficShaper**，强制每条记录的线速尺寸与应用程序载荷独立确定——明文长度不再映射至线速长度。

### 3.2 Control 类

协议帧（CMD_SYN、CMD_FIN、CMD_SETTINGS、CMD_SYNACK、CMD_PADDING）使用 `encrypt_variable_block(PadFill::Zero)`。控制记录的线速大小由 `control_size` 中的**状态感知采样器**确定：

- **握手状态**（前 6 个控制帧）：7 个离散尺寸（33, 37, 46, 51, 64, 69, 82）模拟 HTTP/2 SETTINGS、SETTINGS_ACK、WINDOW_UPDATE 及其合并变体。5% 的帧额外从截断正态分布的 HEADERS 帧分布中采样（C2S: μ=450, σ=120, [250, 800]; S2C: μ=200, σ=50, [100, 400]）。
- **传输状态**（第 6 个控制帧之后）：5 个离散尺寸（33, 37, 41, 46, 54）模拟 PING、WINDOW_UPDATE、SETTINGS_ACK 及其合并变体（无 SETTINGS 尺寸）。10% 的帧从相同的 HEADERS 帧分布中采样。

每个控制帧递增 TrafficShaper 内部的控制帧计数器（`note_control_frame()`），影响 Markov 状态机的握手到传输转换（§3.4）。

### 3.3 TrafficShaper 架构

`TrafficShaper`（每连接实例，由 `SessionWriter::run` 持有）拦截所有应用数据（PSH）写入。全新的 `drive_shaper` 循环替代了旧的 `write_half.write_all(pending)` 全量倾倒方式：

1. **策略查询**: `shaper.next_data_policy(pending_len)` 返回 `ShapePolicy { target_wire_len, delay, fake, allow_full_block }`.
2. **切分截断**: 若 `pending` 超出 `target_wire_len` 所能承载的载荷容量，仅取走对应字节数，其余保留在 `pending` 中供后续迭代处理。如 5000 字节待处理 vs 800 字节目标 → 发出 800 字节记录，保留 4200 字节。
3. **精确填充**: 若 `pending` 小于目标容量，以噪声池填充至精确 `target_wire_len` 后发出。
4. **加密**: `SnowyStream::prepare_data_record(slice, target_wire_len, PadFill::Entropy)` 加密唯一一条线速尺寸等于 `target_wire_len` 的记录。
5. **Flush** + **delay** + **advance**: 记录刷新，若 delay 非零则注入 `tokio::time::sleep(delay)`，随后 shaper 的包序列号和 Markov 状态推进。
6. **虚假交互**: 若策略携带 `fake`，在当前切片发出后向控制队列排队一个 `CMD_PADDING` 请求帧。

以上抹除了被动尺寸痕迹包络：同一应用写入在不同策略下产生完全不同的记录边界，仅取决于 shaper 策略而非内部载荷结构。

### 3.4 Markov 宏状态机

shaper 维护三个覆盖连接全生命周期的宏状态（无硬切分"前 N 包"断崖）：

| 状态　　　　　　　　　 | 尺寸策略　　　　　　　　　　　　　　 | 延迟 | 说明 |
|---|---|---|---|
| `HandshakeShaping`　　　 | 最小拟合（精确匹配载荷）　　　　　 | 无 | Noise 握手阶段；紧密耦合以避免影响认证组帧。 |
| `InteractiveControl`　　| 复用 `control_size` HTTP/2 离散 + HEADERS 分布采样 | 15% 概率对数正态 IAT | 模拟 Web 应用请求/响应模式，记录尺寸可变。 |
| `AsymmetricBulk`　　　　 | 满载 MTU 锚定记录（`max_data_record_wire_len` ≈ 16406） | 无 | 持续大流量传输；解除碎片化封顶，将尺寸锚定至 Web 组帧边界。 |

**转换逻辑**：每次发出包后，依据最近 8 次载荷尺寸的滑动窗口评估状态转换（`RECENT_WINDOW_SIZE = 8`）：
- `InteractiveControl → AsymmetricBulk`: 最近 8 个载荷中至少 `BULK_ENTRY_THRESHOLD`（3）个 = 满载 → 大传输。
- `AsymmetricBulk → InteractiveControl`: 最近 8 个载荷中至少 `BULK_EXIT_THRESHOLD`（6）个 = 小量 → 传输收尾。
- `HandshakeShaping →`: ≥6 控制帧后（握手完成），进入 `InteractiveControl`（若剧本前缀仍有效则以剧本为准）。

### 3.5 Restls 风格剧本引擎

剧本引擎为握手完成后的前 12 个数据包（`SCRIPTED_PACKET_PREFIX`）提供确定性控制。每条规则定义：

```
ScriptRule { len_lo, len_hi, delay: DelaySpec, expect_responses: u8 }
```

- `len_lo..=len_hi`: 记录的内容尺寸（用于计算 `target_wire_len`），均匀随机采样——**与真实载荷不耦合**。
- `delay`（`DelaySpec::None` 或 `DelaySpec::LogNormal{mu,sigma}`）：从拟合的对数正态分布采样的记录间延迟。
- `expect_responses`：若 >0，此数据记录之后立即向对端发出一个 `CMD_PADDING` 请求帧，要求对端回复 M 个独立分片响应。

剧本源为嵌入式默认值（6 条规则），可通过 `traffic_script` 配置字段覆盖（§8）。剧本解析器支持注释（`#`）和空行。配置验证在启动时对每行执行 parse-check，对格式错误行发出非致命警告——格式错误时回退至嵌入式默认脚本。

格式示例：
```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 300~400, Delay: 1.5~0.5, FakeResponse: 2
```

### 3.6 IAT 延迟建模

记录间延迟采用**对数正态分布**（Box-Muller 正态采样 → `sample_log_normal(mu, sigma)` → `Duration::from_micros`），匹配真实 TCP 包间时距的右偏正定分布，优于均匀或指数抖动。Markov `InteractiveControl` 状态以 15% 概率施加延迟；剧本引擎按规则逐条施加。`AsymmetricBulk` 状态零延迟（背靠背发送）以保持吞吐量。

### 3.7 噪声池（熵对齐）

所有整形数据记录中的填充字节及 `CMD_PADDING` 伪造载荷字节，均源自统一的 **8 MiB CSPRNG 预种子噪声池**（`crates/tunnel/src/entropy.rs`，`ENTROPY_POOL`）。该池：
- 启动时从 `rand::thread_rng()`（CSPRNG）预生成（客户端和服务端均需初始化）。
- 通过全局原子游标**环形读取**——无除位置外的任何状态；无分布整形或熵建模。
- 与真实 AEAD 密文**密码学同构**（~8 比特/字节非结构化熵），填充区域在观察者统计空间内与真实加密记录不可区分。

`encrypt_variable_block(pad_fill: PadFill)` 选择填充来源：`PadFill::Zero` 用于控制路径，`PadFill::Entropy` 用于整形数据路径。这替代了原有的零填充和内联 `rand::thread_rng()` 填充。

### 3.8 虚假交互引擎 (CMD_PADDING)

`CMD_PADDING`（操作码 0x08）是 session 级别控制帧，载荷格式为：

```
| flag(1B) | m(1B) | junk(噪声池) |
  flag = 0 → 请求　　 1 → 应答
```

- **请求**（`flag=0`）：由发送方在剧本规则或策略指定 `expect_responses = M` 时在**Control**队列（优先）上发出。伪造字节源自噪声池。
- **应答**（`flag=1`）：接收方解码请求后，立即向发送方回吐 `M` 个**独立拆分**的应答帧（每个为独立噪声池填充的 Control 记录，尺寸各异），强制破坏应用数据层的一问一答对称性。
- 应答帧永不递交到任何数据流——在帧处理层静默丢弃（作为读取活动以保活空闲超时计时器）。
- 请求与应答的伪造字节均源自噪声池，保持所有填充字节与密文同构。

### 3.9 握手后线速 Record 尺寸参考

握手完成后每条记录均为 0x17 记录，带 5 字节头部（`| 0x17 | 0x03 | 0x03 | len(u16 BE) |`）后接 Noise 加密密文。每条明文：`[length_prefix(2B, BE) | payload | padding(噪声池) | inner_content_type(1B, 0x17)]`。

| Record 类型　　　　　 | 线速尺寸（= 5 + 密文）　　　　　　 | 尺寸控制 | 填充来源 |
|---|---|---|---|
| 整形数据记录　　　　 | **shaper 决定**（24–16406）　　　 | `TrafficShaper::next_data_policy` → `prepare_data_record(target_wire_len, Entropy)` | 噪声池 |
| 控制帧　　　　　　　 | 离散（33–82）或 HEADERS（124–824）→ §3.2 | `control_size::next_control_size` → `prepare_control_record(payload, size)` | 零 |
| Flight3 CCS　　　　　| **6**（未加密）　　　　　　　　　　| 硬编码 | — |
| Flight3 Finished 幽灵 | **58**　　　　　　　　　　　　　　| 37 + 16 AEAD + 5 header | — |
| Flight3 H2 幽灵　　　| **86 / 92 / 98**　　　　　　　　　 | context-hash 选择变体 | — |
| close_notify 告警　　 | **24**（3 + 16 + 5）　　　　　　　 | 硬编码 `[01 00 15]` | — |
| 幽灵 record（服务端）| **5 + cache_size**　　　　　　　　| 伪装缓存 | 噪声池（原 ENTROPY_POOL） |

---

## 4. Session 多路复用

### 4.1 帧协议

每帧 7 字节头部：

```
| cmd (1) | stream_id (4, BE) | data_len (2, BE) | payload (0–65535) |
```

| 命令　　 | 操作码 | 用途　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| ----------| --------| --------------------------------------------------------------------------|
| SYN　　　| 0x01　 | 打开流　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| PSH　　　| 0x02　 | 推送数据　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| FIN　　　| 0x03　 | 关闭流（半关闭）　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| SETTINGS | 0x04　 | Session 能力协商　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| SYNACK　 | 0x07　 | 流打开确认　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| PADDING　| 0x08　 | 虚假交互引擎（§3.8）；请求/应答噪声池帧　　　　　　　　　　　　　　　　|

### 4.2 流水线流打开

客户端流打开将 `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` 融合为一次 control-class coalesced write flush。全新 session 的首个 stream 通过 `DeferredUnsent` 状态延迟 SYN 发送——SETTINGS 帧（保存在 `PendingClientSettings` 中）和 SYN 帧被缓冲在 `Stream` 对象中而不发送。首次 `write()` 调用时，`write_gather_open()` 通过 `PendingClientSettingsGuard` 取出 SETTINGS 帧，置于 SYN 之前，然后追加目标和数据 PSH 帧。全部帧经由 `coalesce_encoded_frames` 压缩后，通过单次 `submit_write_packets`（`FlushBehavior::Immediate`）发出，完成单次合并写入。

服务端在验证目标、解析 DNS、建立中继连接之后才发送 SYNACK。因此 SYNACK 确认的是真实可达性——不仅仅是流接受。

### 4.3 空闲拆除

Session 读取循环（`run_read_loop`）使用 pinned `tokio::time::sleep` 定时器（`idle_timeout_with_jitter_secs`，默认 45 秒，来自配置）。每次成功读取时，定时器重置为 `now + idle_duration`。若定时器触发时无活跃流、无待处理入站流、无待打开流（`is_idle_timeout_eligible()`），Session 优雅拆除：发送 Noise 加密的 TLS `close_notify` 告警（0x15），随后 TCP FIN。不发送应用层心跳（CMD_PING）——内核 TCP keepalive（空闲 60 秒，间隔 30 秒，3 次重试）作为死端检测机制。

---

## 5. 防主动探测

### 5.1 解密失败

当收到的 0x17 记录 Noise AEAD 解密失败（`read_message` 返回 `Err`）时，隧道**不会**发送任何告警。取而代之：

1. 立即将 `close_notify_written` 设为 `true`，防止正常的 `close_notify` 被发送。
2. 返回 `InvalidData` IO 错误。
3. Session 读取循环收到错误后拆除 TCP 连接。
4. 不会向对端写回任何字节——连接静默关闭。

对端观察到的要么是 TCP FIN，要么是 RST（取决于操作系统），无 TLS 层告警载荷，阻止了依赖区分告警类型的主动探测。

### 5.2 Pre-Auth 回落

在 Noise 认证提交前的失败（非 TLS 首包、认证失败、SNI 不匹配、握手超时）可选择将客户端流量透明转发到伪装端点。受以下限制：

| 限制　　　　　 | 值　　　　　　　　　　　　　　　　　 |
| ----------------| --------------------------------------|
| 全局并发回落　 | 384–768（启动时随机）　　　　　　　　|
| 每 IP 并发回落 | 12–24（随机）　　　　　　　　　　　　 |
| 回落连接超时　 | 2–5 秒（随机）　　　　　　　　　　　 |
| IP 冷却阈值　　| 3000–4200 秒窗口内 75–150 次 → 240–420 秒冷却 |

---

## 6. 指纹预设

`fingerprint` 配置字段选择 ClientHello 生成策略：

| 预设　　　　　　　　　　　　　| 来源　　　　　　　　　　　| 加密套件顺序　　　　　　　　　　　　　　　　| Key Share 组　　　　　　　　 |
| -------------------------------| ---------------------------| ---------------------------------------------| ------------------------------|
| `firefox`　　　　　　　　　　 | 捕获的 bootstrap hex blob | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519, SECP256R1　　　　　　|
| `rustls`　　　　　　　　　　　| 原生 rustls TLS 1.3　　　 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | X25519, SECP256R1, SECP384R1 |
| `python-openssl` / `baseline` | 捕获的 bootstrap hex blob | AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM | X25519, SECP256R1　　　　　　|

Firefox 和 Python-OpenSSL 预设精确保留捕获的记录形态（扩展顺序、填充、记录长度）。Rustls 预设使用实时 rustls 生成并对 GREASE 进行轮换。

可通过 `template_path` 用自定义 ClientHello hex 文件覆盖 Firefox/Python-OpenSSL 模板。Rustls 预设忽略 `template_path`。

---

## 7. 错误处理状态机

```
                                 ClientHello 到达
                                        │
                        ┌───────────────┴───────────────────┐
                        │ 首包是 0x16？                      │
                        └────────────┬───────┬──────────────┘
                                  是 │       │ 否
                                     │       ▼
                                     │   Pre-Auth 回落
                                     │   → 透明转发
                                     │
                                     ▼
                             Noise 认证 + 计数器重放 + MAC
                             （单一原子检查）
                                     │
                        ┌────────────┴────────────────────┐
                        │ 全部通过？                       │
                        └─────────────┬──────────────┬────┘
                                  是  │              │ 否
                                      │              ▼
                                      │         Pre-Auth 回落
                                      │         （涵盖 Noise、
                                      │          计数器 MAC、重放）
                                      │
                        ┌─────────────┴─────────────────────┐
                        │ SNI 匹配伪装？                     │
                        └─────────────┬──────────────┬──────┘
                                  是  │              │ 否
                                      │              ▼
                                      │         Pre-Auth 回落
                                      │
                                      ▼
                                  提交计数器重放
                                      │
                                      ▼
                                   合成伪装回放
                                      │
                                      ▼
                                  Noise 传输已建立
                                      │
                        ┌─────────────┴────────────────────┐
                        │ 0x17 解密错误？                   │
                        └─────────────┬────────────────────┘
                                  是  │
                                      ▼
                            静默关闭 —— 不发送告警。
                             TCP FIN 或 RST（取决于 OS）。
```

---

## 8. Session 配置

`session` 块（可选，位于客户端 outbounds 和服务端 inbounds 的 `settings` 下）控制每个 Session 的行为：

| 字段　　　　　　　　　　 | 类型　　　　 | 默认值　　　　　 | 说明 |
|---|---|---|---|
| `max_streams_per_session` | usize　　　 | 256　　　　　　　| 每个隧道 Session 最大并发多路复用流数。 |
| `idle_timeout_secs`　　　| u64　　　　 | 45　　　　　　　 | Session 空闲拆除超时（含 ±10% 抖动）。 |
| `traffic_script`　　　　　| optional string |（嵌入式默认）　 | Restls 风格剧本，控制握手完成后前 12 个数据包的行为（§3.5）。示例：`"Length: 200~250, Delay: 0, FakeResponse: 0\nLength: 300~400, Delay: 2.0~0.5, FakeResponse: 1"`。格式错误的规则在启动时触发非致命警告，并回退至嵌入式默认脚本。 |

嵌入式默认剧本：
```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 180~220, Delay: 1.5~0.6, FakeResponse: 0
Length: 250~350, Delay: 0, FakeResponse: 1
Length: 300~400, Delay: 2.0~0.5, FakeResponse: 0
Length: 200~300, Delay: 0, FakeResponse: 1
Length: 400~600, Delay: 3.0~0.7, FakeResponse: 0
```

剧本前缀用尽后，TrafficShaper 的 Markov 状态机（§3.4）在连接剩余生命周期中掌管尺寸与延迟策略。Markov 转换参数无配置暴露——它们源自最近载荷尺寸的滑动窗口且方向对称。
