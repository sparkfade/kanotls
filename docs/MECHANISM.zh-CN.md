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

## 3. 数据流双模分布

### 3.1 Bulk 类

大数据写入（应用层载荷 > 16382 字节）切分为完整的 TLS 记录：

- **明文**：`[length_prefix(2B, BE) | data(16382B) | inner_content_type(1B, 0x17)]` = 16385 字节
- **密文**（ChaChaPoly）：16385 + 16 = 16401 字节
- **线速记录**：5（header）+ 16401 = **16406 字节**

当 `poll_flush()` 排空剩余数据（0 < n ≤ 16382 字节）时，`encrypt_padded_block()` 应用**抖动填充**：80% 概率使用指数分布填充（λ = 0.050295，CDF(32) ≈ 0.80）并截断至 32 字节；20% 概率填充至满载 16385 字节明文。这产生自然的尾记录线速尺寸分布（n + 24 到 16406），避免可识别的精确截断或固定满载块指纹。

### 3.2 Control 类

微帧（CMD_SYN、CMD_FIN）使用 `encrypt_variable_block()`。控制记录的线速大小由 `control_size` 中的**状态感知采样器**确定：

- **握手状态**（前 6 个控制帧）：7 个离散尺寸（33, 37, 46, 51, 64, 69, 82）模拟 HTTP/2 SETTINGS、SETTINGS_ACK、WINDOW_UPDATE 及其合并变体。5% 的帧额外从截断正态分布的 HEADERS 帧分布中采样（C2S: μ=450, σ=120, [250, 800]; S2C: μ=200, σ=50, [100, 400]）。
- **传输状态**（第 6 个控制帧之后）：5 个离散尺寸（33, 37, 41, 46, 54）模拟 PING、WINDOW_UPDATE、SETTINGS_ACK 及其合并变体（无 SETTINGS 尺寸）。10% 的帧从相同的 HEADERS 帧分布中采样。

`FlowDirection`（C2S vs S2C）为 HEADERS 帧截断正态采样器选择参数，产生方向差异化的分布。

控制记录优先级更高：任何累积的 bulk 数据在 `tx_agg_buf` 中先被排空（作为精确大小的 padded block），然后再发送控制记录。

### 3.3 熵源

| 填充位置　　　　　　　　　　　　| 来源　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| ---------------------------------| -----------------------------------------------------------|
| 幽灵记录载荷（服务端）　　　　　| `ENTROPY_POOL` — 8 MiB 预种子 `thread_rng` 字节，循环读取 |
| 幽灵记录结构头部　　　　　　　　| 硬编码 16 字节伪造票据头部 `[0x22, 0x00, ...]`　　　　　　|
| `encrypt_variable_block()` 尾部 | 零字节，末字节 = `0x17`（内部内容类型）　　　　　　　　　 |
| `encrypt_full_block()` 尾部 | 末字节 = `0x17`（内部内容类型），无其他空闲空间 |

### 3.4 握手后线速 Record 尺寸参考

握手完成后线路上每条记录均为 0x17（应用数据）记录，带有 5 字节头部（`| 0x17 | 0x03 | 0x03 | len(u16 BE) |`），后接 Noise 加密的密文。内部每条明文的前 2 字节为长度前缀，其后为实际载荷，可选零填充，末尾 1 字节为内部内容类型（`0x17` 为应用数据，`0x15` 为告警）——匹配 TLS 1.3 `TLSInnerPlaintext` 结构。

| Record 类型 | 明文公式 | 密文（= 明文 + 16） | 线速（= 5 + 密文） | 示例（n 字节数据） |
|---|---|---|---|---|
| 满载 bulk 块 | `2 + 16382 + 1 = 16385` | 16401 | **16406** | n = 16382 → 16406 |
| 尾 bulk（抖动填充） | `2 + n + 1` + 填充至 16385 | 明文 + 16 | **n + 24** 至 **16406** | n = 866 → ~890–16406 |
| 控制帧 | `2 + payload` + 零填充 + 1B ICT 至目标 | 目标 + 16 | 离散 33-82 或 124-824（见 §3.2） | CMD_SYN（7B）: 69 |
| Flight3 CCS | — | — | **6**（未加密） | — |
| Flight3 Finished 幽灵 | 37 | 53 | **58** | — |
| Flight3 H2 幽灵 | 65 / 71 / 77 | 81 / 87 / 93 | **86 / 92 / 98** | context-hash 选择变体 |
| close_notify 告警 | 3（`[01 00 15]`） | 19 | **24** | — |
| 幽灵 record（服务端） | 来自伪装缓存的 size | size + 16 | **5 + cache_size** | 前 16B = 伪造票据头部 |

尾 bulk 记录使用抖动填充——80% 最多携带 32 字节填充（指数分布），20% 填充至满载块尺寸 16406 字节。

---

## 4. Session 多路复用

### 4.1 帧协议

每帧 7 字节头部：

```
| cmd (1) | stream_id (4, BE) | data_len (2, BE) | payload (0–65535) |
```

| 命令　　 | 操作码 | 用途　　　　　　 |
| ----------| --------| ------------------|
| SYN　　　| 0x01　 | 打开流　　　　　 |
| PSH　　　| 0x02　 | 推送数据　　　　 |
| FIN　　　| 0x03　 | 关闭流（半关闭） |
| SETTINGS | 0x04　 | Session 能力协商 |
| SYNACK　 | 0x07　 | 流打开确认　　　 |

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
