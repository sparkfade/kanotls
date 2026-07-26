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

**多用户认证。** 服务端入站配置 `users` 列表（`{name, password}`），每个密码在启动时经 `derive_psk()` 展开为独立的 `derived_psk`。握手时服务端将每个候选 PSK 逐一与 ClientHello 校验——临时密钥解掩、`read_message()`、计数器 MAC——首个全部通过的 PSK 即标识出认证用户（`crates/tunnel/src/server/mod.rs` 中的 `authenticate_client_hello()`）。单次探测仅需若干哈希加一次 AEAD 解密，因此每握手成本随用户数线性增长。识别出的用户名会附加到连接上，路由引擎可通过规则的 `auth_user` 字段按用户分流。

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

服务端启动时，`validate_camouflage_endpoint()` 向参考端点发送 4 次由模板实例化的新鲜 ClientHello（与客户端相同的 Firefox 模板）。每次 flight 经指纹化（random/session_id/key_share 置零，padding 扩展规范化）后，按 per-指纹 key 和指纹族 baseline key（指纹哈希的前 8 个 hex 字符）进行缓存。

### 2.3 逐连接回放

客户端连接时：

1. 通过 `stable_client_hello_fingerprint()` 对 ClientHello 进行指纹化。
2. 服务端查找最佳缓存 profile（偏好完整 profile：rank 3 = 同时具有 server_records 和 app_data_sizes）。
3. 若没有完整缓存 profile，`fetch_camouflage_flight()` 向参考端点执行实时获取（含 refresh-gate 去重）。
4. `establish_synthetic_camouflage_tunnel()`：
   - 将客户端的 `session_id` 回显到缓存的 ServerHello 中。长度不匹配说明缓存 profile 与本连接不自洽，此时拒绝握手，而不是回显一个客户端从未发送过的值（RFC 8446 §4.1.3）。
   - 用新鲜随机字节替换 ServerHello 的 `random`（若存在降级哨兵则保留）。
   - **逐连接重新生成 ServerHello `key_share`**（服务端临时 ECDHE 公钥），按组区分：X25519 与 secp256r1 用 ring 生成真实密钥对（随机字节不是合法曲线点；而随机 32 字节「X25519 公钥」有一半概率置最高位，真实 u 坐标则恒不置位）；X25519MLKEM768 的 ML-KEM-768 密文部分是密集打包，均匀随机字节即合法且分布正确。若不做这一步，缓存 profile 被逐字节回放，服务端会在每条连接上交出**同一个** ECDHE 公钥——整个缓存生命周期内至多 4 个变体、按 300–3000 秒刷新周期轮换。真实端点不可能重复公钥，因此每流只存 32 字节、两条连接即可零误报识别。遇到不支持的组时 fail closed，而不是把该指纹发出去。
   - 发送所有可见握手记录。
   - 发送前缀 0x17 记录（太小而无法承载 Noise 载荷），逐连接以 `rand::thread_rng()` 新鲜填充。
   - 发送封装在 0x17 记录中的 Noise 应答（大小匹配缓存的首个 app_data 大小，Noise 服务端公钥 XOR 掩码在前 32 字节中）。
   - 发送幽灵 0x17 记录（按缓存大小），逐连接以 `rand::thread_rng()` 新鲜填充。

> **ServerHello 之后服务端写上线的每个明文字节，都必须逐连接新鲜随机。** 这些记录冒充的是 NewSessionTicket——在 TLS 1.3 中它位于加密 record 内，线上就是均匀随机的 AEAD 密文。此前有两处违反该原则，现已移除：
>
> - 每条幽灵记录前置一个固定的 16 字节 `22 00…00`「伪造会话票据结构头部」。它是常量、是明文、且位于固定偏移，一次 16 字节 `memcmp` 即可命中，误报率 2^-128，而且在每条连接中重复最多 255 次。
> - 载荷取自一个进程级 8 MiB 熵池并循环读取，于是不同连接的载荷之间出现逐字节相同的数百字节片段。真实 AEAD 密文永不重复，这种复用让观察者能把不同流归并到同一服务端进程。实测：每连接约 1.8 KB 幽灵载荷时，约 64 条连接内即出现碰撞。
>
> `crates/tunnel/src/server/wire_tests.rs` 现在对这两条性质各有断言（无常量字节位置、跨连接无相同 16 字节窗口），回归即 CI 失败。

### 2.4 后台刷新

每个 (host, port) 对的守护进程每 300–3000 秒（随机化）使用与探测相同的 ClientHello 指纹刷新 profile。

---

## 3. 主动流量整形

### 3.1 设计缘由

v1.0 原始双模分布（§3.1–3.4）被动地在 `BLOCK_DATA_CAPACITY`（16382）边界上切分应用载荷，并以概率性尾部填充（80/20 抖动）包裹余量。这导致内部 TLS 明文尺寸被直接映射至外部线速记录尺寸，暴露结构指纹（例如 5000 字节的证书会生成 16382 + 16382 + 1236 = 三条记录，其尺寸对被动观察者泄露内部握手形态）。v1.1 引入**自上而下的主动 TrafficShaper**，强制每条记录的线速尺寸与应用程序载荷独立确定——明文长度不再映射至线速长度。

### 3.2 Control 类

协议帧（CMD_SYN、CMD_FIN、CMD_SETTINGS、CMD_SYNACK、CMD_PADDING）使用 `encrypt_variable_block`。控制记录的线速大小由 `control_size` 中的**状态感知采样器**确定：

- **握手状态**（前 6 个控制帧）：7 个离散尺寸（33, 37, 46, 51, 64, 69, 82）模拟 HTTP/2 SETTINGS、SETTINGS_ACK、WINDOW_UPDATE 及其合并变体。5% 的帧额外从截断正态分布的 HEADERS 帧分布中采样（C2S: μ=450, σ=120, [250, 800]; S2C: μ=200, σ=50, [100, 400]）。
- **传输状态**（第 6 个控制帧之后）：5 个离散尺寸（33, 37, 41, 46, 54）模拟 PING、WINDOW_UPDATE、SETTINGS_ACK 及其合并变体（无 SETTINGS 尺寸）。10% 的帧从相同的 HEADERS 帧分布中采样。

每个控制帧递增 TrafficShaper 内部的控制帧计数器（`note_control_frame()`），影响 Markov 状态机的握手到传输转换（§3.4）。

### 3.3 TrafficShaper 架构

`TrafficShaper`（每连接实例，由 `SessionWriter::run` 持有）拦截所有应用数据（PSH）写入。全新的 `drive_shaper` 循环替代了旧的 `write_half.write_all(pending)` 全量倾倒方式：

1. **策略查询**: `shaper.next_data_policy(pending_len)` 返回 `ShapePolicy { target_wire_len, delay, fake, allow_full_block }`.
2. **切分截断**: 若 `pending` 超出 `target_wire_len` 所能承载的载荷容量，仅取走对应字节数，其余保留在 `pending` 中供后续迭代处理。如 5000 字节待处理 vs 800 字节目标 → 发出 800 字节记录，保留 4200 字节。
3. **精确填充**: 若 `pending` 小于目标容量，以零字节填充至精确 `target_wire_len` 后发出。
4. **加密**: `SnowyStream::prepare_data_record(slice, target_wire_len)` 加密唯一一条线速尺寸等于 `target_wire_len` 的记录。
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

**转换逻辑**：每次发出包后，通过**概率平滑**评估状态转换。概率值 `p_bulk = pending_len / max_pending_flush_size` 驱动转换：几乎满载的待发送缓冲区强力推动进入 `AsymmetricBulk`，而接近排空的缓冲区则推动退出至 `InteractiveControl`（退出概率上限 85%）。这替代了 v1.1 的确定性阈值，通过连续概率渐变避免状态边界振荡。

### 3.5 声明式流量脚本引擎

流量脚本引擎为握手完成后的数据包序列提供确定性、可回放的控制，包括记录尺寸、记录间延迟、以及对端交互信号。它由用户提供（或嵌入式默认）的规则列表驱动，规则按 `packet_seq % 规则数` 循环应用，直到 `packet_seq` 达到脚本的 `stop` 计数（默认等于规则数）。这使得操作者可以预编程一条模拟已知目标应用（如 TLS 加密的视频流或 Web 浏览会话）的包尺寸序列，而不将记录尺寸耦合至实际隧道载荷。

**规则结构：**
```
ScriptRule { len_lo, len_hi, delay: DelaySpec, expect_responses: u8, fake_jitter: i32 }
```

| 字段 | 含义 |
|---|---|
| `len_lo`..`len_hi` | 该记录中嵌入的**应用内容字节数**，从区间内均匀随机采样。Shaper 计算 `target_wire_len = MIN_DATA_WIRE_LEN + (len_lo..len_hi)`，按该精确线速尺寸填充并加密。真实待发送数据最多消耗 `len_lo..len_hi` 字节；若积压少于目标，由零字节填充补齐；若积压更多，仅切走一块，余量保留供后续迭代。 |
| `delay` | `DelaySpec::None`（零延迟）或 `DelaySpec::LogNormal{mu_ms, sigma_ms}`（从拟合对数正态分布采样的记录间暂停）。详见 §3.6。 |
| `expect_responses` | 若 `> 0`，发送方在 **Control** 通道上排入一个 `CMD_PADDING` 请求（opcode 0x08）。对端解码请求后，向发送方回吐 `M` 个独立拆分的应答帧（§3.8）。该字段设为 `0` 表示普通单向数据规则。 |
| `fake_jitter` | fake 响应的落点抖动：规则每次触发时，从 `[min(0,k), max(0,k)]` 区间内相对触发记录均匀采样一个偏移。负偏移在触发记录**之前**发出请求（归于前一条记录的槽位）；零固定于触发记录；正偏移延后发出，待目标记录发出时释放（脚本达到 `stop` 时全部剩余强制释放）。该机制将掩护帧簇与其触发记录解相关。 |

**脚本生命周期与融合窗口：**

脚本运行 `stop` 个数据包（`stop` 默认等于规则数；更大的 `stop` 会重复循环规则）。最后一个脚本包发出后，引擎进入长度为 `SCRIPT_BLEND_WINDOW = 6` 包的**平滑融合窗口**。在此窗口内，切入 Markov 状态机（§3.4）的概率从 0% 线性渐变至 100%，消除 "前 N 包后突变" 的硬切分断崖，产生在线速尺寸分布上不可指纹的平滑切换。

融合窗口结束后，TrafficShaper 的 Markov 状态机接管连接剩余生命周期。Markov 转换参数无配置暴露——它完全由待发送缓冲区压力通过概率 `p_bulk` 渐变推导（§3.4）。

**脚本后整形开关（`post_script_shaping`）：** 可选配置字段 `session.post_script_shaping` 选择脚本用尽后的行为。默认 `"markov"` 如上所述（融合窗口 → Markov 机）。`"off"` 关闭脚本后的全部整形：`packet_seq` 达到 `stop` 后，后续每条记录精确承载当前积压载荷（线速尺寸 = 积压 + 固定 record 开销），零延迟、无 Fake 帧、无融合窗口——从此刻起明文尺寸直接映射至线速尺寸。两种模式下 bulk fast path 与 bulk 迟滞（§3.4）均保持优先。除 `"markov"`/`"off"` 外的取值在启动时触发非致命警告并按未设置处理。

**数据包收发示例——客户端→服务端，3 规则脚本：**

假设 `traffic_script` 内容：
```json
"traffic_script": [
  "0=L:200-250,D:0,F:0",
  "1=L:300-400,D:2.0-0.5,F:1",
  "2=L:180-220,D:1.5-0.6,F:0"
]
```

实际应用数据积压：6000 字节。

| 包序号 | 规则 | 采样 `len` | 消耗真实数据 | 线速 record 尺寸 | 发出后行为 |
|---|---|---|---|---|---|
| 1 | 规则 0 | 215 | 215 字节（来自积压） | `MIN_DATA_WIRE_LEN + 215`（≈ 239） | Flush。无延迟。`packet_seq` → 1。剩余积压：5785。 |
| 2 | 规则 1 | 362 | 362 字节 | `MIN_DATA_WIRE_LEN + 362`（≈ 386） | Flush。`sleep(log_normal(2.0, 0.5))`。随后：在 Control 通道排入 `CMD_PADDING(flag=0, m=1)`。剩余积压：5423。 |
| 3 | 规则 2 | 197 | 197 字节 | `MIN_DATA_WIRE_LEN + 197`（≈ 221） | Flush。`sleep(log_normal(1.5, 0.6))`。剩余积压：5226。 |

第 3 包后脚本耗尽。第 4–9 包在**6 包融合窗口**中发出：每包有递增概率（≈17%, 33%, 50%, 67%, 83%, 100%）由 Markov 机控制而非循环脚本。第 10 包起完全由 Markov 控制。

**服务端在线速上看到的内容（以第 2 包序列为例）：**

1. 服务端收到线速尺寸 ≈ 386 字节的 0x17 record → Noise 解密 → 明文 `[len_prefix(2B) | 362B payload | padding | 0x17]` → 交付 362 字节至对应 stream。
2. 经对数正态采样暂停（例如 1.8 ms）后，服务端收到一条**Control 类 0x17 record**，内含 `CMD_PADDING` 请求（`cmd=0x08, flag=0, m=1`）。
3. 服务端帧处理器立即向客户端回吐 1 条 `CMD_PADDING` 应答帧（`cmd=0x08, flag=1`，零填充垃圾字节），通过 Control 通道发出。该应答帧为独立的 0x17 record，尺寸从 Control 类传输态池中采样（33–82 或 124–824 字节，§3.2）。
4. 应答帧永不递交至任何 stream——在 session 帧处理层解码后静默丢弃，仅作为掩护流量打破一问一答对称性。

脚本源为嵌入式默认值（6 条规则，见 §8），可通过 `traffic_script` 配置字段覆盖。配置值为 JSON 字符串数组：一个可选的 `stop=N` 控制条目，后跟带索引的规则 `i=L:...,D:...,F:...`（索引必须与规则的 0 基位置一致）。配置验证在启动时解析该数组；任一格式错误的条目触发非致命警告并回退至嵌入式默认脚本。

`L` 字段除 `lo-hi` 外还接受 `base?range` 语法：在 shaper 构建时每连接采样一次 `base + U[0, range]`，该值在此连接的生命周期内固定。解析完成后，每个连接在 `TrafficShaper::new` 中对脚本做随机化：规则顺序按随机偏移轮转，且每条规则的长度区间乘以独立的 U[0.85, 1.20] 采样（钳制至 ≥ 1 且 ≤ 数据 record 容量），因此「位置 → 尺寸」映射跨连接不恒定。

格式示例：
```json
"traffic_script": [
  "stop=4",
  "0=L:200-250,D:0,F:0",
  "1=L:300-400,D:1.5-0.5,F:2?-1"
]
```

### 3.6 IAT 延迟建模

记录间延迟的非零延迟规格如下（`DelaySpec::None` 表示零延迟）：

- **`DelaySpec::LogNormal { mu_ms, sigma_ms }`**：对数正态分布（Box-Muller 正态采样 → `sample_log_normal(mu, sigma)` → `Duration::from_micros`），匹配真实 TCP 包间时距的右偏正定分布，优于均匀或指数抖动。

Markov `InteractiveControl` 状态以 15% 概率施加延迟；脚本引擎按规则逐条施加。`AsymmetricBulk` 状态零延迟（背靠背发送）以保持吞吐量。

### 3.7 记录填充

整形数据记录与 `CMD_PADDING` 伪造载荷中的填充字节一律为**零**——这正是 RFC 8446 §5.4 为 TLS 1.3 record padding 规定的取值。

此前的设计从一个 8 MiB CSPRNG 熵池取这些字节，理由是填充必须「与真实 AEAD 密文密码学同构」。该论证不成立：这些字节全部位于 `encrypt_variable_block` 的**明文**一侧，随后由 ChaCha20-Poly1305 加密，观察者看到的密文对任何明文输入都是均匀随机的。熵池在这些位置没有任何收益，代价却是每条记录一次跨 8 MiB 的 cache-hostile 拷贝，外加一个全局争用的原子游标。该模块已删除。

真正需要随机性的是合成伪装回放（§2.3）中服务端以明文写上线的字节；那些字节逐连接取自 `rand::thread_rng()`。

### 3.8 虚假交互引擎 (CMD_PADDING)

`CMD_PADDING`（操作码 0x08）是 session 级别控制帧，载荷格式为：

```
| flag(1B) | m(1B) | junk(零填充) |
  flag = 0 → 请求　　 1 → 应答
```

- **请求**（`flag=0`）：由发送方在脚本规则或策略指定 `expect_responses = M` 时在**Control**队列（优先）上发出。伪造字节为零（随帧一并加密）。
- **应答**（`flag=1`）：接收方解码请求后，立即向发送方回吐 `M` 个**独立拆分**的应答帧（每个为独立的 Control 记录，尺寸各异），强制破坏应用数据层的一问一答对称性。
- 应答帧永不递交到任何数据流——在帧处理层静默丢弃（作为读取活动以保活空闲超时计时器）。
- 请求与应答的伪造字节均为零；它们位于 AEAD 的明文一侧，内容在线上不可见。

### 3.9 握手后线速 Record 尺寸参考

握手完成后每条记录均为 0x17 记录，带 5 字节头部（`| 0x17 | 0x03 | 0x03 | len(u16 BE) |`）后接 Noise 加密密文。每条明文：`[length_prefix(2B, BE) | payload | padding(零) | inner_content_type(1B, 0x17)]`。

| Record 类型　　　　　 | 线速尺寸（= 5 + 密文）　　　　　　 | 尺寸控制 | 填充来源 |
|---|---|---|---|
| 整形数据记录　　　　 | **shaper 决定**（24–16406）　　　 | `TrafficShaper::next_data_policy` → `prepare_data_record(target_wire_len)` | 零（RFC 8446 §5.4）|
| 控制帧　　　　　　　 | 离散（33–82）或 HEADERS（124–824）→ §3.2 | `control_size::next_control_size` → `prepare_control_record(payload, size)` | 零 |
| Flight3 CCS　　　　　| **6**（未加密）　　　　　　　　　　| 硬编码 | — |
| Flight3 Finished 幽灵 | **58**　　　　　　　　　　　　　　| 37 + 16 AEAD + 5 header | — |
| Flight3 H2 幽灵　　　| **86 / 92 / 98**　　　　　　　　　 | context-hash 选择变体 | — |
| close_notify 告警　　 | **24**（3 + 16 + 5）　　　　　　　 | 硬编码 `[01 00 15]` | — |
| 幽灵 record（服务端）| **5 + cache_size**　　　　　　　　| 伪装缓存 | 逐连接新鲜 CSPRNG |

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
| PADDING　| 0x08　 | 虚假交互引擎（§3.8）；请求/应答掩护帧　　　　　　　　　　　　　　　　　|

### 4.2 流水线流打开

客户端流打开将 `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` 融合为一次 control-class coalesced write flush。全新 session 的首个 stream 通过 `DeferredUnsent` 状态延迟 SYN 发送——SETTINGS 帧（保存在 `PendingClientSettings` 中）和 SYN 帧被缓冲在 `Stream` 对象中而不发送。首次 `write()` 调用时，`write_gather_open()` 通过 `PendingClientSettingsGuard` 取出 SETTINGS 帧，置于 SYN 之前，然后追加目标和数据 PSH 帧。全部帧经由 `coalesce_encoded_frames` 压缩后，通过单次 `submit_write_packets`（`FlushBehavior::Immediate`）发出，完成单次合并写入。

服务端在验证目标、解析 DNS、建立中继连接之后才发送 SYNACK。因此 SYNACK 确认的是真实可达性——不仅仅是流接受。

### 4.3 空闲拆除

Session 读取循环（`run_read_loop`）使用 pinned `tokio::time::sleep` 定时器（`idle_timeout_with_jitter_secs`，默认 45 秒，来自配置）。每次成功读取时，定时器重置为 `now + idle_duration`。若定时器触发时无活跃流、无待处理入站流、无待打开流（`is_idle_timeout_eligible()`），Session 优雅拆除：发送 Noise 加密的 TLS `close_notify` 告警（0x15），随后 TCP FIN。不发送应用层心跳（CMD_PING）——内核 TCP keepalive（空闲 60 秒，间隔 30 秒，3 次重试）作为死端检测机制。

> **仅服务端生效**：客户端 Session 的空闲生命周期由连接池的 idle drain / soft TTL 统一驱动，`run_read_loop` 中该分支在客户端侧通过 `idle_teardown_enabled = !is_client` 屏蔽。

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

Noise 认证提交之前的**每一种**失败，都会把客户端流量透明转发到伪装端点。对于输入驱动的失败，这是唯一的可观测结果，且各类输入之间完全一致：

| 输入 | 可观测结果 |
|---|---|
| 非 TLS 首记录（`GET / HTTP/1.1` 等） | 透明转发 |
| 认证失败（PSK / MAC 错误、重放的 ClientHello） | 透明转发 |
| 缺失 SNI / SNI 不匹配 | 透明转发 |
| 记录头声明长度超限 | 透明转发 |
| 发送不足 5 字节，或记录截断/挂起 | 转发**恰好收到的那些字节** |

两条对抗探测的关键性质：

- **交给转发的缓冲只含客户端真实发送过的字节。** 此前的实现会先按声明长度 `resize(len, 0)` 预填零再读，于是一个挂起的 ClientHello 会被零填充到「完整」后转发给伪装端点——真实站点随即收到一个客户端从未发出的请求并回以告警。
- **任何输入都无法翻转行为。** 此前有两条 fail-closed 路径，各自 5 字节即可稳定触发：声明长度超限时瞬时关闭（且接收队列尚有未读数据，`close(2)` 发出的是 RST 而非 FIN），什么都不发时在恰好 T+10.000 秒得到静默 FIN。两者现在都走转发，且初始记录截止时间逐连接从 8–15 秒采样，不再有可测量的常量时刻。

转发本身双向传播半关闭（不转发 `shutdown(SHUT_WR)` 会让上游一直挂到它自己的 `keepalive_timeout`，与直连行为可区分），并且仅在两个方向都持续 300 秒无流量后才终止——该值远大于常见上游空闲超时，因此正常情况下总是上游先关闭、本上限不可观测；它的唯一作用是防止永久静默的连接把 permit 与 fd 钉死。

转发受以下限额约束：

| 限制 | 值 |
|---|---|
| 全局并发回落 | 512（固定值） |
| 每 IP 并发回落 | 16（固定值） |
| 回落连接超时 | 3 秒（固定值） |
| IP 冷却阈值 | 3600 秒窗口内 112 次 → 300 秒冷却 |
| 并发握手中连接数 | 512（固定值） |

**限额耗尽时**连接无法转发，统一走唯一出口 `emit_indistinguishable_close()`：

1. 关闭前先有界排空接收队列（上限 64 KiB / 200 毫秒），使关闭恒为干净 FIN。不排空时 `close(2)` 会在 FIN 之后再发 RST，于是「探测者发过数据」与「什么都没发」得到不同的关闭序列——仅凭一条连接即可据此分类服务器。
2. 关闭前随机等待 200–3000 毫秒，使「瞬时关闭」（限额耗尽）与「固定时刻关闭」（读超时）都不再呈现可测量的常量。

这是唯一不会抵达伪装端点的路径，且只能通过耗尽限额到达——探测者无法用任何构造出的输入直接触发。

## 6. 指纹预设

`fingerprint` 配置字段选择 ClientHello 生成策略：

| 预设　　　　　　　　　　　　　| 来源　　　　　　　　　　　| 加密套件顺序　　　　　　　　　　　　　　　　| Key Share 组　　　　　　　　　　　　　　　 |
| -------------------------------| ---------------------------| ---------------------------------------------| ---------------------------------------------|
| `firefox`　　　　　　　　　　 | 捕获的 bootstrap hex blob | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519MLKEM768, X25519, SECP256R1　　　　　 |

`firefox` 是唯一受支持的取值（亦为默认值）；其他 `fingerprint` 取值在配置校验时直接报错。该预设精确保留捕获的记录形态（扩展顺序、填充、记录长度），并对所有模板（内嵌或 `template_path` 自定义 hex）在加载时统一执行两项规范化：

1. **扩展剔除**：移除 ECH（`0xFE0D`/`0x014A`）、`early_data`（`0x0119`）、`use_srtp`（`0x001C`）和 `0x0022`——它们要么破坏与普通 TLS 1.3 端点的互操作性，要么对伪装没有价值。
2. **结构合法的 X25519MLKEM768 份额**：每条连接重新生成 1216 字节混合份额——768 个系数从 [0, 3329) 均匀采样（与真实 ML-KEM.768 ek 同分布），后接随机 rho/X25519 字节。支持 ML-KEM 的服务器（OpenSSL 3.5+）会在解码时校验系数范围，对随机垃圾回 `illegal_parameter`；合法份额同时在统计上与真实 Firefox 密钥不可区分。

可通过 `template_path` 用自定义 ClientHello hex 文件覆盖内嵌 Firefox 模板，规范化同样生效。

---

## 7. 错误处理状态机

探测者能通过选择输入抵达的每一条分支，最终都落在透明转发上。唯一不抵达伪装端点的出口以限额耗尽为前提，任何输入都无法按需触发。

```
                          TCP 连接被 accept
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ 握手限额尚有余量？                 │
                        └─────────────┬────────┬─────────────┘
                                  是  │        │ 否
                                      │        ▼
                                      │   emit_indistinguishable_close
                                      │   （排空后延迟 200–3000ms 再 FIN）
                                      ▼
                    读取初始记录（截止时间 8–15 秒，逐连接抖动）
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ 是完整的 0x16 记录？               │
                        └─────────────┬────────┬─────────────┘
                                  是  │        │ 否 — 非 TLS 类型、
                                      │        │ 声明长度超限、超时、
                                      │        │ EOF、不足 5 字节
                                      │        ▼
                                      │  Pre-Auth 回落
                                      │  → 透明转发**恰好收到的**字节
                                      ▼
                          Noise 认证 + 计数器重放 + MAC
                          （单次原子检查）
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ 全部通过？                         │
                        └─────────────┬────────┬─────────────┘
                                  是  │        │ 否
                                      │        ▼
                                      │  Pre-Auth 回落
                                      │  （覆盖 Noise、计数器
                                      │    MAC 与重放）
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ SNI 与伪装主机匹配？               │
                        └─────────────┬────────┬─────────────┘
                                  是  │        │ 否
                                      │        ▼
                                      │  Pre-Auth 回落
                                      │
                                      ▼
                             提交计数器重放
                                      │
                                      ▼
                              合成伪装回放
                                      │
                                      ▼
                           Noise 传输态建立
                                      │
                        ┌─────────────┴───────────────────────┐
                        │ 0x17 解密失败？                     │
                        └─────────────┬───────────────────────┘
                                  是  │
                                      ▼
                         静默关闭——不发送任何告警。
                         TCP FIN 或 RST（取决于操作系统）。
```

任何无法建立的 Pre-Auth 回落——全局/每 IP 并发耗尽、IP 处于冷却、上游不可达——都会落到图顶部同一个 `emit_indistinguishable_close`，因此所有限额耗尽的结果共享同一种可观测行为（§5.2）。

---

## 8. Session 配置

`session` 块（可选，位于客户端 outbounds 和服务端 inbounds 的 `settings` 下）控制每个 Session 的行为：

| 字段　　　　　　　　　　 | 类型　　　　 | 默认值　　　　　 | 说明 |
|---|---|---|---|
| `max_streams_per_session` | usize　　　 | 256　　　　　　　| 每个隧道 Session 最大并发多路复用流数。 |
| `idle_timeout_secs`　　　| u64　　　　 | 45　　　　　　　 | Session 空闲拆除超时（含 ±10% 抖动）。 |
| `traffic_script`　　　　　| optional string array |（嵌入式默认）　 | 声明式流量脚本，控制握手完成后数据包的行为（§3.5）：一个可选的 `stop=N` 条目加带索引的规则 `i=L:lo-hi,D:d,F:f`。规则按 `packet_seq % N` 循环应用直到 `stop`，随后以 6 包平滑融合窗口过渡至 Markov 机。示例：`["stop=4", "0=L:200-250,D:0,F:0", "1=L:300-400,D:2.0-0.5,F:1"]`。格式错误的脚本在启动时触发非致命警告，并回退至嵌入式默认脚本。 |
| `post_script_shaping` | optional string | `"markov"` | 脚本后整形模式（§3.5）。`"markov"`（默认）：融合窗口 → Markov 机。`"off"`：脚本用尽后按积压精确尺寸发出，零延迟、无 Fake 帧。非法取值在启动时触发非致命警告并按未设置处理。 |

嵌入式默认脚本（以 `traffic_script` 配置语法展示）：
```
stop=6
0=L:200-250,D:0,F:0
1=L:180-220,D:1.5-0.6,F:0
2=L:250-350,D:0,F:1
3=L:300-400,D:2.0-0.5,F:0
4=L:200-300,D:0,F:1
5=L:400-600,D:3.0-0.7,F:0
```

脚本规则用尽后（通过平滑融合窗口衔接进入 Markov 机），TrafficShaper 的 Markov 状态机（§3.4）在连接剩余生命周期中掌管尺寸与延迟策略。Markov 转换参数无配置暴露——它们源自待发送缓冲区压力通过概率 `p_bulk` 渐变且方向对称。
