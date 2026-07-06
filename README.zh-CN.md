# kanotls

用于传输协议研究的实验性 TLS + Noise 隧道。

English docs: [README.md](README.md) | 机制: [docs/MECHANISM.zh-CN.md](docs/MECHANISM.zh-CN.md)

## 架构

```
应用层:        SOCKS5 / HTTP CONNECT 代理
会话层:        多路复用 stream + 单次 flush 流打开 + 主动流量整形 TLS record 分发
传输层:        Noise_NNpsk0 (X25519 + ChaChaPoly + BLAKE2s) 封装在 TLS 1.3 record 内
外层 TLS:      ClientHello 预设 (firefox / rustls / python-openssl)
               + 缓存参考站点 record 形态镜像
UDP:           SOCKS5 UDP ASSOCIATE 通过 UDP-over-TCP stream data 承载
```

kanotls 使用独立 Noise 通道完成端点认证和载荷加密。Noise 临时公钥通过 PSK 派生掩码嵌入 ClientHello 的 `random` 字段；`key_share` 扩展承载**独立的** TLS 层 X25519 临时密钥用于与参考站点完成可见握手，消除了两字段间的统计关联。服务端回放缓存的参考端点 record 形态——仅在首次启动和定期后台刷新时才实际连接伪装端点。

认证与重放失败走受限的 pre-auth 回落路径。读取阶段（认证后）失败走 fail-closed 永不回落。回落连接带有显式防滥用限制（并发上限、每 IP 限制、连接超时、IP 信誉冷却）。AEAD 解密失败静默关闭连接——不发送告警，不以 `close_notify` 泄露。

详细机制参考：[docs/MECHANISM.zh-CN.md](docs/MECHANISM.zh-CN.md)

## 功能

- **多路复用 session**：多条逻辑 stream 共享一条外层 TLS 隧道，每条 stream 有独立背压和有界缓冲。
- **流水线流打开**：客户端将 `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` 凝聚为单次 coalesced write flush。服务端延迟 SYNACK 至目标中继连接建立完成，因此 SYNACK 确认的是真实可达性而非仅仅流接受。
- **UDP-over-TCP**：SOCKS5 UDP datagram 封装为 session stream 数据，保留地址信息。
- **XOR 掩码隐藏密钥**：Noise 临时公钥 XOR 编码于 ClientHello `random` 中。确定性强、无状态、无曲线点编码偏置。
- **按会话计数器防重放**：40 位随机会话标识符与 24 位严格单调序列号。服务端使用每会话命名空间的 64 位滑动窗口位图（LRU，4096 条目）加 600 秒临时密钥重放缓存（65536 条目）纵深防御。
- **按会话临时密钥协商**：每会话使用新鲜 Noise 临时密钥进行 X25519 密钥交换，预共享密钥认证（最小 32 字节）。不同会话使用独立临时密钥，单会话密钥泄露不影响其他会话。
- **HTTP CONNECT only**：HTTP inbound 仅接受 authority-form `CONNECT host:port`。
- **目的地址保护**：服务端拒绝 loopback / private / link-local / multicast / broadcast / unspecified / CGNAT / reserved（`240.0.0.0/4`）/ port-0。
- **单二进制部署**：`cargo build --release`。角色从入站协议类型自动识别。
- **TLS 指纹预设**：`firefox`、`rustls`、`python-openssl`（别名 `baseline`）。默认 `firefox`。支持通过 `template_path` 注入自定义 ClientHello hex。
- **空闲拆除**：每 session 使用 pin-reset 空闲定时器，每次成功读取时重置。空闲超时（默认 45 秒，可配置，含 ±10% 抖动）触发优雅 session 拆除（Noise 加密的 `close_notify` + TCP FIN）。无应用层心跳——内核 TCP keepalive（空闲 60 秒，间隔 30 秒，Linux 上 3 次重试）处理死端检测。
- **主动流量整形**：全生命周期 Markov 状态机（TrafficShaper）主动对每条应用数据（0x17）记录进行切分、填充和节拍控制，记录线速尺寸由 shaper 策略决定——明文长度不再映射至线速尺寸。支持可选的声明式流量脚本（`traffic_script`）对握手后包序列进行确定性控制，包括记录间 Delay 时序（对数正态或预录制 IAT 回放）与非对称 FakeResponse 交互（CMD_PADDING）。所有填充字节源自统一的 8 MiB CSPRNG 预种子噪声池，与真实 AEAD 密文密码学同构。
- **模板热重载**：`template_path` hex 文件每 30 秒轮询 mtime 变更。更新时文件被重新解析，模板缓存失效，新连接立即使用新 ClientHello 而无需重启。解析失败记录警告但保留旧模板。

## 快速开始

### 构建

```bash
cargo build --release
```

使用 `kanotls --config config.json` 启动。角色自动判断：`"protocol": "tunnel"` 入站 → 服务端模式；`socks5` / `socks` / `http` 入站 → 客户端模式。

### 服务端

```jsonc
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "tag": "tls-in",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "tunnel",
      "settings": {
        "password": "8P5KbMuExWh6yNJI2xHLiWWfACIS5wYDHo7PVdTbOgj93mVrYKj7Q89VjJwfW8Oj",
        "camouflage": {
          "host": "example.com",
          "port": 443
        },
        "session": {
          "max_streams_per_session": 256,
          "idle_timeout_secs": 45,
          "traffic_script": "Length: 200~250, Delay: 0, FakeResponse: 0\nLength: 180~220, Delay: 1.5~0.6, FakeResponse: 0\nLength: 250~350, Delay: 0, FakeResponse: 1\nLength: 300~400, Delay: 2.0~0.5, FakeResponse: 0\nLength: 200~300, Delay: 0, FakeResponse: 1\nLength: 400~600, Delay: 3.0~0.7, FakeResponse: 0"
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "direct"
    },
    // SOCKS5 上游代理出站（详见服务端出站章节）：
    // {
    //   "tag": "socks5-out",
    //   "protocol": "socks5",
    //   "settings": {
    //     "address": "127.0.0.1",
    //     "port": 1080,
    //     "username": "user",
    //     "password": "pass"
    //   }
    // }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inbound_tag": ["tls-in"],
        "outbound_tag": "direct"
      }
    ]
  }
}
```

### 客户端

```jsonc
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 5080,
      "protocol": "socks5"
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "tunnel",
      "settings": {
        "server": "1.2.2.4",
        "port": 443,
        "password": "8P5KbMuExWh6yNJI2xHLiWWfACIS5wYDHo7PVdTbOgj93mVrYKj7Q89VjJwfW8Oj",
        "tls": {
          "sni": "example.com",
          "insecure": false,
          "fingerprint": "firefox",
          "template_path": "/etc/kanotls/firefox_client_hello.hex"
        },
        "session": {
          "max_streams_per_session": 256,
          "idle_timeout_secs": 45,
          "traffic_script": "Length: 200~250, Delay: 0, FakeResponse: 0\nLength: 180~220, Delay: 1.5~0.6, FakeResponse: 0\nLength: 250~350, Delay: 0, FakeResponse: 1\nLength: 300~400, Delay: 2.0~0.5, FakeResponse: 0\nLength: 200~300, Delay: 0, FakeResponse: 1\nLength: 400~600, Delay: 3.0~0.7, FakeResponse: 0"
        }
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inbound_tag": ["socks-in"],
        "outbound_tag": "proxy"
      }
    ]
  }
}
```

## 服务端一键部署（Linux）

```bash
curl -fsSL https://raw.githubusercontent.com/sparkfade/kanotls/main/install.sh | sudo bash
```

脚本会从 GitHub Releases 下载最新预编译二进制，安装至 `/usr/local/bin/kanotls`，创建 `/etc/kanotls/` 并写入骨架配置，安装 systemd 单元文件。

脚本为交互式——首先选择语言（中文/English），然后进入菜单（安装 / 更新 / 卸载）。安装和更新可选稳定版或预发布版。

安装完成后，编辑 `/etc/kanotls/config.json`：
- 替换占位密码
- 设置 `camouflage.host` 和 `camouflage.port` 为参考端点地址

启动服务：

```bash
sudo systemctl enable --now kanotls
sudo journalctl -u kanotls -f
```

程序默认从 `/etc/kanotls/config.json`（Linux）或 `/usr/local/etc/kanotls/config.json`（macOS）读取配置，回退至可执行文件同目录下的 `config.json`。可通过 `--config` 指定自定义路径。

## 配置说明

### 密码

预共享密钥，客户端和服务端必须完全一致。最少 32 字节。配置验证会拒绝包含占位子串的密码（`change_me`、`placeholder`、`replace_me`、`your_password_here`、`fill_me`）。生成：

```bash
openssl rand -base64 48
```

### 日志级别

`trace` / `debug` / `info` / `warn` / `error`。优先级：`log.level` → 环境变量 `RUST_LOG` → 默认 `info`。

### 路由

按 `inbounds[].tag` 匹配。客户端运行时目前仅支持单一出站——所有路由规则的 `outbound_tag` 必须指向 `outbounds[0].tag`。服务端支持多出站，规则可引用任意已配置的出站 tag。

### 协议别名

客户端入站 `protocol` 字段接受 `"socks"` 作为 `"socks5"` 的别名。

### Session 调优

`idle_timeout_secs` 默认值为 45 秒（含 ±10% 抖动）。配置验证接受 `[1, 3600]` 区间。客户端侧运行时被 clamp 到 `[5, 3600]`。服务端侧不做 clamp。

空闲拆除机制：Session 读取循环使用 pin-reset 空闲定时器（默认 45 秒，含 ±10% 抖动），每次成功读取时重置。定时器触发且无活跃流时，Session 优雅拆除（Noise 加密的 `close_notify` + TCP FIN）。不发送应用层心跳——内核 TCP keepalive 处理死端检测。

服务端和客户端在启动时均预分配 8 MiB 的噪声熵池，用于主动流量整形的记录填充和合成伪装回放 ghost record 载荷。

### 流量脚本

`traffic_script` 是一个**可选**的声明式程序，用于控制握手完成后应用数据记录的尺寸、时序和对端交互行为。省略时使用嵌入式默认脚本（6 条规则，即上文配置示例所示）。`session.max_streams_per_session`、`session.idle_timeout_secs` 和 `session.traffic_script` 均为可选字段——各字段适用于哪一侧请参见[字段参考](#字段参考)。

脚本每行一条规则；`#` 注释和空行会被忽略。规则通过 `packet_seq % 规则数` 循环应用，用尽后在 6 包窗口内平滑过渡至 Markov 整形机（参见 docs/MECHANISM.zh-CN.md §3.5）。每条规则包含三个字段：

| 字段 | 格式 | 含义 |
|-------|--------|---------|
| `Length` | `lo~hi` | 本条记录的应用内容字节数，从 `[lo, hi]` 区间均匀采样。整形器填充（或切分）至对应线速尺寸，使线速尺寸与真实载荷尺寸解耦。要求 `lo` ≤ `hi`。**必填。** |
| `Delay` | `0` \| `mu~sigma` \| `n` | 记录间停顿。`0` = 无延迟；`mu~sigma` = 对数正态分布，参数单位毫秒；单个整数 `n` = `ln(n)~0.5` 的简写。 |
| `FakeResponse` | 整数 | 若 `> 0`，本条记录 flush 后发送方排队一个 `CMD_PADDING` 请求，对端回复相应数量的非对称掩护帧（打破请求/响应对称性）。`0` 表示禁用。 |

示例（JSON 字符串中每个 `\n` 为字面换行符）：

```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 300~400, Delay: 2.0~0.5, FakeResponse: 1
```

格式错误的规则为非致命错误：启动时记录警告并整体回退至嵌入式默认脚本。

### TLS 配置

外层 TLS ClientHello 按 `fingerprint` 预设生成。`insecure`（默认 `false`）在原生 rustls ClientHello 生成路径中跳过 TLS 证书验证——端点认证和载荷加密完全由 `Noise_NNpsk0` 与配置的 `password` 提供，外层 TLS 仅提供伪装。服务端使用缓存的参考端点 profile 完成可见 record 回放；`template_path` 可用捕获的 hex 文件覆盖 Firefox/Python-OpenSSL 模板（`rustls` 忽略此字段）。

### TLS 指纹预设

| 值 | 来源 | 加密套件顺序 | Key Share 组 |
|---|------|-------------|-------------|
| `firefox` | 捕获的 bootstrap | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519, SECP256R1 |
| `rustls` | 原生 rustls TLS 1.3 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | X25519, SECP256R1, SECP384R1 |
| `python-openssl` | 捕获的 bootstrap | AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM | X25519, SECP256R1 |

`baseline` 是 `python-openssl` 的别名。默认：`firefox`。

### 自定义 ClientHello：`template_path`

提供捕获的 hex 文件（`template_path`）覆盖 Firefox/Python-OpenSSL 模板。文件每 30 秒通过 mtime 轮询**热重载**——更新 hex 文件后新连接立即使用新 ClientHello，无需重启进程。（解析失败记录警告但保留旧模板。）

```json
"tls": {
  "sni": "example.com",
  "fingerprint": "firefox",
  "template_path": "/etc/kanotls/firefox_client_hello.hex"
}
```

使用 Wireshark 抓取（过滤器 `tls.handshake.type == 1`），将 ClientHello 复制为 hex stream，粘贴到文件中。解析器自动清除空格、换行、`0x` 前缀和数组括号——直接粘贴 Wireshark 原始输出即可。

部署前验证：

```bash
python3 update_firefox_template.py --input firefox_client_hello.hex --check-only
```

## 握手认证机制

ClientHello 保持正常 TLS record 结构。TLS 1.3 中预期为随机的字段承载已认证的 Noise 数据：

- **`random[0..32]`**：Noise initiator 临时 X25519 公钥，经 PSK 派生掩码 XOR 编码。
- **`key_share`（扩展 0x0033，X25519 条目）**：独立的 X25519 临时密钥用于可见 TLS 握手——与 Noise 密钥无关。
- **`session_id[0..16]`**：Noise PSK 认证的首条消息 AEAD tag。
- **`session_id[16..24]`**：连接计数器，XOR 掩码编码。
- **`session_id[24..32]`**：对计数器和 `random` 前缀的 PSK 派生 MAC；字节 31 低 2 位清零。

服务端 XOR 反掩码，依次校验 Noise tag、计数器 MAC、每会话单调性（滑动窗口），并通过重放缓存拒绝重放临时密钥。

## Session 多路复用

### 帧协议

7 字节头部：`| cmd (1) | stream_id (4, BE) | data_len (2, BE) | payload (…) |`

| 命令 | 操作码 | 用途 |
|---|---|---|
| SYN | 0x01 | 打开流 |
| PSH | 0x02 | 推送数据 |
| FIN | 0x03 | 关闭流 |
| SETTINGS | 0x04 | Session 能力协商 |
| SYNACK | 0x07 | 流打开确认 |
| PADDING | 0x08 | 虚假交互引擎 |

每帧最大载荷：65535 字节。相邻帧在限制内合并后再加密为 TLS 记录。

### 流水线流打开

客户端将 `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` 凝聚为一次 coalesced flush。Session 的首个 stream 延迟 SYN 发送至首次 `write()` 调用，届时 SETTINGS + SYN + 目标 + 数据被压缩入单次 coalesced write。服务端延迟 SYNACK 至目标中继连接建立完成。

### 连接池（客户端）

- **目标池大小**：由指纹族、SNI 和时段种子决定（默认 4–16）
- **错峰启动**：初始连接以抖动延迟（50–2500 ms）错峰建立
- **Soft TTL 轮换**：120–300 秒（种子决定），连接停止接受新 stream
- **空闲排干**：30 秒无活跃 stream → 连接关闭
- **按需扩容**：仅在有等待者时创建新连接
- **负载感知选择**：按 stream 数和缓冲流量选择连接

### 空闲拆除

Session 读取循环使用 pinned `tokio::time::sleep` 定时器，每次成功读取时重置。空闲超时 tick（默认 45 秒，可配置含 ±10% 抖动）时，session 检查是否存在活跃流；若无活跃流，则发送 Noise 加密的 TLS `close_notify`（0x15）和 TCP FIN，优雅拆除连接。不在应用层发送 CMD_PING 心跳——内核 TCP keepalive（空闲 60 秒，间隔 30 秒，Linux 上 3 次重试）作为死端检测机制。

## 伪装端点缓存

1. **启动**：从参考端点采集 4 次完整 flight，按 ClientHello 指纹 key 缓存（LRU，1024 条目，每 key 4 变体）。
2. **逐连接回放**：缓存的 ServerHello（session_id 回显，random 随机替换）、可见握手 record、0x17 记录合成回放。Noise 应答作为 0x17 记录注入，大小匹配首个缓存的 app_data 大小。
3. **后台刷新**：每个 (host, port) 守护进程每 300–3000 秒（随机化）刷新。

`reference` 可作为 `camouflage` 的别名。参考端点必须支持 TLS 1.3。阻止地址：private、loopback、link-local、multicast、unspecified、CGNAT。

### Pre-Auth 回落

在提交到认证隧道路径之前，部分失败可回落为对伪装端点的受限透明转发：

| 限制 | 值 |
|---|---|
| 全局并发回落 | 384–768（启动时随机） |
| 每 IP 并发回落 | 12–24（随机） |
| 回落连接超时 | 2–5 秒（随机） |
| IP 冷却阈值 | 3000–4200 秒窗口内 75–150 次 → 240–420 秒冷却 |

Fail-closed 失败（读取阶段错误、超大 record）永不回落。

### 服务端出站

服务端出站定义中继流量的出口路径。支持两种协议：

| 协议 | 说明 | 配置项 |
|------|------|--------|
| `direct` | 直接 TCP/UDP 中继到目标 | _(无)_ |
| `socks5` | 通过上游 SOCKS5 代理中继 | `address`（主机）、`port`（1–65535）、可选 `username`/`password`（RFC 1929 认证） |

两种协议均支持 TCP CONNECT 和 UDP ASSOCIATE。路由引擎通过 `routing.rules` 中的 `inbound_tag` → `outbound_tag` 匹选出站。当无规则匹配时，使用第一个出站（`outbounds[0]`）作为确定性回退。

SOCKS5 出站示例：

```jsonc
{
  "tag": "socks5-out",
  "protocol": "socks5",
  "settings": {
    "address": "127.0.0.1",
    "port": 1080,
    "username": "user",
    "password": "pass"
  }
}
```

路由规则选择出站：

```jsonc
"routing": {
  "rules": [
    {
      "type": "field",
      "inbound_tag": ["tls-in"],
      "outbound_tag": "socks5-out"
    }
  ]
}
```

### 回落调优（`camouflage.fallback`）

服务端配置可选 `camouflage.fallback` 对象（所有字段均有默认值）：

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `max_global` | 512 | 全局最大并发连接数 |
| `max_per_ip` | 16 | 每 IP 最大并发连接数 |
| `min_lifetime_secs` | 30 | 最小连接生命周期（秒） |
| `max_lifetime_secs` | 3600 | 最大连接生命周期（秒） |
| `cooldown_duration_secs` | 300 | 限速后冷却时长（秒） |
| `connect_timeout_secs` | 3 | 连接超时（秒） |

> 上述字段在配置解析时被接受以保证前向兼容性。实际 pre-auth 回落限额在启动时从硬编码范围内随机（见上方 Pre-Auth 回落表）。配置值预留用于未来的可调回落功能。

## 设计不变量

| 约束                      | 值                                   |
| ---------------------------| --------------------------------------|
| Noise 协议                | `NNpsk0_25519_ChaChaPoly_BLAKE2s`    |
| PSK 最小长度              | 32 字节                              |
| 最大并发握手              | 512                                  |
| 最大活跃 session           | 4096                                 |
| 计数器滑动窗口            | 64 位位图（允许最多落后 63）          |
| 重放缓存                  | 65536 条目，600 秒保留              |
| 单 session 最大并发 stream | 4096（配置验证上限）                  |

## 字段参考

### 顶层字段

| 字段 | 角色 | 说明 |
|------|------|------|
| `log.level` | 双方 | `trace` / `debug` / `info` / `warn` / `error`（默认 `info`） |
| `routing.rules` | 双方 | sing-box 风格入站 tag 路由规则 |

### 入站字段

| 字段 | 角色 | 说明 |
|------|------|------|
| `tag` | 双方 | 路由标签 |
| `listen` | 双方 | 监听地址（客户端：必须为 loopback IP 字面量） |
| `port` | 双方 | 监听端口 |
| `protocol` | 服务端 | `"tunnel"` |
| `protocol` | 客户端 | `"socks5"` / `"socks"` / `"http"` |
| `settings.password` | 服务端 | 预共享密钥，最少 32 字节 |
| `settings.camouflage.host` | 服务端 | 参考 TLS 1.3 端点主机名（DNS 名称；不接受 IP 字面量） |
| `settings.camouflage.port` | 服务端 | 参考端点端口 |
| `settings.camouflage.fallback` | 服务端 | Pre-auth 回落调优（见下文） |
| `settings.session.max_streams_per_session` | 双方 | 可选。单 session 最大并发 stream 数（默认 256） |
| `settings.session.idle_timeout_secs`       | 双方 | 可选。session 空闲超时秒数（默认 45） |
| `settings.session.traffic_script`          | 双方 | 可选。声明式流量脚本（参见 docs/MECHANISM.zh-CN.md §3.5 及上文「流量脚本」章节） |

### 出站字段（服务端）

| 字段 | 协议 | 说明 |
|------|------|------|
| `tag` | 双方 | 路由标签 |
| `protocol` | 双方 | `"direct"` 或 `"socks5"` |
| `settings.address` | `socks5` | 上游 SOCKS5 代理地址（IP 或主机名） |
| `settings.port` | `socks5` | 上游 SOCKS5 代理端口（1–65535） |
| `settings.username` | `socks5` | 可选 RFC 1929 用户名（可为空） |
| `settings.password` | `socks5` | 可选 RFC 1929 密码（需配合用户名；可为空） |

### 出站字段（客户端）

| 字段 | 说明 |
|------|------|
| `tag` | 路由标签 |
| `protocol` | 必须为 `"tunnel"` |
| `settings.server` | 服务端地址 |
| `settings.port` | 服务端端口 |
| `settings.password` | 预共享密钥（最少 32 字节） |
| `settings.tls.sni` | 外层 ClientHello SNI（DNS 名称；不接受 IP 字面量） |
| `settings.tls.insecure` | 可选。跳过 rustls 路径 TLS 证书验证（默认 `false`）。仅影响原生 rustls ClientHello 生成；Noise 提供端点认证。 |
| `settings.tls.fingerprint` | 可选。预设：`firefox`（默认）、`rustls`、`python-openssl`、`baseline` |
| `settings.tls.template_path` | 可选。捕获的 ClientHello hex 文件路径；覆盖 Firefox/Python-OpenSSL 模板（`rustls` 忽略）。每 30 秒 mtime 轮询热重载。 |
| `settings.session.idle_timeout_secs` | 可选。session 空闲超时（默认 45，客户端侧 clamp 至 [5, 3600]） |
| `settings.session.max_streams_per_session` | 可选。单 session 最大并发 stream 数（默认 256，验证至 [1, 4096]） |
| `settings.session.traffic_script` | 可选。声明式流量脚本（参见 docs/MECHANISM.zh-CN.md §3.5 及上文「流量脚本」章节） |

## 握手序列

```
客户端                                    服务端                         参考 TLS 端点
  |                                         |                                   |
  |--- ClientHello (0x16) ----------------->|                                   |
  |   Noise e 在 random; tag/counter/MAC    |--- ClientHello ------------------>|
  |   在 session_id; 独立 ks                 |<-- ServerHello + flight ----------|
  |                                         |                                   |
  |<-- ServerHello (0x16) ------------------|  (session_id 回显, random 替换)    |
  |<-- 前缀 0x17 (可选) ---------------------|  (取自噪声熵池)                     |
  |<-- Noise 应答 (0x17) --------------------|  (e, ee + KTL1 + ghost_count)     |
  |<-- 幽灵 0x17 × N ------------------------|  (伪造票据头部 + 熵池填充)         |
  |                                         |                                   |
  |--- CCS (6 B 明文) ---------------------->|  (0x14 记录，未加密)                |
  |--- Finished 幽灵 (0x17, 58 B) ---------->|  (Noise 加密于 0x17)               |
  |--- H2 SETTINGS 幽灵 (0x17) ------------->|  (65–77 B 明文变体)                |
  |                                         |                                   |
  |<====== Noise transport (0x17) =========>|  整形: TrafficShaper 决定 / ctrl HTTP/2 模拟尺寸|
```

## 许可证

GPL-3.0-or-later
