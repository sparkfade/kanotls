# kanotls

用于传输协议研究的实验性 TLS + Noise 隧道。

English docs: [README.md](README.md) | 机制: [docs/MECHANISM.zh-CN.md](docs/MECHANISM.zh-CN.md)

## 架构

```
应用层:        SOCKS5 / HTTP CONNECT 代理
会话层:        多路复用 stream + 单次 flush 流打开 + 主动流量整形 TLS record 分发
传输层:        Noise_NNpsk0 (X25519 + ChaChaPoly + BLAKE2s) 封装在 TLS 1.3 record 内
外层 TLS:      ClientHello 预设 (firefox)
               + 缓存参考站点 record 形态镜像
UDP:           SOCKS5 UDP ASSOCIATE 通过 UDP-over-TCP stream data 承载
```

kanotls 使用独立 Noise 通道完成端点认证和载荷加密。Noise 临时公钥通过 PSK 派生掩码嵌入 ClientHello 的 `random` 字段；`key_share` 扩展承载**独立的** TLS 层 X25519 临时密钥用于与参考站点完成可见握手，消除了两字段间的统计关联。服务端回放缓存的参考端点 record 形态——仅在首次启动和定期后台刷新时才实际连接伪装端点。

认证与重放失败走受限的 pre-auth 回落路径。读取阶段（认证后）失败走 fail-closed 永不回落。回落连接带有显式防滥用限制（全局并发 512、单 IP 并发 16、连接超时 3 秒）；单 IP 累计速率冷却已移除——它会让 113 条普通连接就把该 IP 推进「不转发」分支，制造一个内容级的零误报判别。AEAD 解密失败静默关闭连接——不发送告警，不以 `close_notify` 泄露。

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
- **TLS 指纹**：`firefox`（捕获的 bootstrap，唯一预设）。支持通过 `template_path` 注入自定义 ClientHello hex。**不剥离任何扩展**——上线的扩展类型列表与捕获的真实 Firefox 逐项相同（15 个），ClientHello 总长 1884 字节。逐连接重新生成：系数合法的 X25519MLKEM768 混合份额、真实 P-256 曲线点、以及**一个** X25519 密钥写入 0x001d 与混合份额两处（真实 Firefox 复用同一密钥，NSS Bug 1902119），ECH GREASE 的 `config_id`/`enc`/`payload` 三个字段亦逐连接刷新。
- **空闲拆除**：服务端 Session 使用 pin-reset 空闲定时器，每次成功读取时重置。空闲超时（默认 **75 秒**，可配置，**常量、无抖动**，取 nginx `keepalive_timeout` 默认值）触发优雅 session 拆除（Noise 加密的 `close_notify` + TCP FIN）。客户端侧连接空闲生命周期由连接池全权管理（**115 秒**空闲排干，对齐 Firefox `network.http.keep-alive.timeout`；soft TTL **3600 秒**，对齐 nginx `keepalive_time` 默认 1 小时），`idle_timeout_secs` 仅服务端生效。无应用层心跳——内核 TCP keepalive 对齐 Firefox 默认值（空闲 **600 秒**、间隔 **1 秒**、**4 次**探测，不加抖动）。H2 层另有客户端发起的空闲 PING（58 秒无对端到达触发，观测窗口内抑制），拆除前发 GOAWAY。
- **主动流量整形**：全生命周期 Markov 状态机（TrafficShaper）主动对每条应用数据（0x17）记录进行切分、填充和节拍控制，记录线速尺寸由 shaper 策略决定——明文长度不再映射至线速尺寸。支持可选的声明式流量脚本（`traffic_script`）对握手后包序列进行确定性控制，包括记录间 Delay 时序（对数正态或预录制 IAT 回放）与非对称 FakeResponse 交互（CMD_PADDING）。记录填充为零字节（RFC 8446 §5.4）——它位于 AEAD 的明文一侧，内容在线上不可见。
- **模板热重载**：`template_path` hex 文件每 30 秒轮询 mtime 变更。更新时文件被重新解析，模板缓存失效，新连接立即使用新 ClientHello 而无需重启。解析失败记录警告但保留旧模板。

## 快速开始

### 构建

```bash
cargo build --release
```

使用 `kanotls --config config.json` 启动。角色自动判断：`"protocol": "kanotls"` 入站 → 服务端模式；`socks5` / `socks` / `http` 入站 → 客户端模式。

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
      "protocol": "kanotls",
      "settings": {
        "users": [
          { "name": "1", "password": "8P5KbMuExWh6yNJI2xHLiWWfACIS5wYDHo7PVdTbOgj93mVrYKj7Q89VjJwfW8Oj" },
          { "name": "2", "password": "mVf9k2Qz8wYxN3pL7rT5vB1nM4cX6sD0gH8jK2lP9qR4tU7wE3yI6oA5zS1dF8g" }
        ],
        "camouflage": {
          "host": "example.com",
          "port": 443
        },
        "session": {
          "max_streams_per_session": 256,
          "idle_timeout_secs": 75,
          "traffic_script": [
            "stop=6",
            "0=L:200-250,D:0,F:0",
            "1=L:180-220,D:1.5-0.6,F:0",
            "2=L:250-350,D:0,F:1",
            "3=L:300-400,D:2.0-0.5,F:0",
            "4=L:200-300,D:0,F:1",
            "5=L:400-600,D:3.0-0.7,F:0"
          ],
          "post_script_shaping": "markov" // 可选
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
        "inbound": ["tls-in"],
        "auth_user": ["1"],
        "outbound": "socks5-out"
      },
      {
        "inbound": ["tls-in"],
        "outbound": "direct"
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
      "protocol": "kanotls",
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
          "idle_timeout_secs": 75,
          "traffic_script": [
            "stop=6",
            "0=L:200-250,D:0,F:0",
            "1=L:180-220,D:1.5-0.6,F:0",
            "2=L:250-350,D:0,F:1",
            "3=L:300-400,D:2.0-0.5,F:0",
            "4=L:200-300,D:0,F:1",
            "5=L:400-600,D:3.0-0.7,F:0"
          ],
          "post_script_shaping": "markov" // 可选
        }
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "inbound": ["socks-in"],
        "outbound": "proxy"
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
- 替换 `settings.users` 中的占位密码
- 设置 `camouflage.host` 和 `camouflage.port` 为参考端点地址

启动服务：

```bash
sudo systemctl enable --now kanotls
sudo journalctl -u kanotls -f
```

程序默认从 `/etc/kanotls/config.json`（Linux）或 `/usr/local/etc/kanotls/config.json`（macOS）读取配置，回退至可执行文件同目录下的 `config.json`。可通过 `--config` 指定自定义路径。

## 配置说明

### 用户

服务端入站通过 `settings.users` 列表（`{name, password}` 条目）对客户端进行认证。每个密码都是独立的预共享密钥（最少 32 字节）；同一入站内用户名与密码均必须唯一。配置验证会拒绝包含占位子串的密码（`change_me`、`placeholder`、`replace_me`、`your_password_here`、`fill_me`）。生成：

```bash
openssl rand -base64 48
```

客户端出站携带单个 `settings.password`，对应服务端某个用户的密码。认证通过后，用户名会附加到连接上，可通过路由规则的 `auth_user` 字段按用户分流。

### 管理 API

一个刻意保持小型的可选 HTTP API，为后续「一台中控管多个节点」的面板做准备。服务端配置中不存在 `api` 段时完全关闭：

```json
"api": {
  "listen": "127.0.0.1:9090",
  "token": "<openssl rand -hex 24>"
}
```

所有端点都要求 `Authorization: Bearer <token>`，路径都在 `/api/v1` 下：

| 端点 | 说明 |
|---|---|
| `GET /api/v1/node` | 节点状态 `{version, online, enabled, uptime_secs, active_connections, users, enabled_users}`。中控逐节点轮询：可达即在线，不可达即离线。 |
| `PUT /api/v1/node/enabled` | 节点代理**服务**的启停，请求体 `{"enabled": false}`（也接受 POST）。停用后端口照常监听，但所有连接都回落到伪装站点——对外就是一台普通 Web 服务器；API 保持可达以便重新启用。状态持久化到 `inbounds[0].enabled`。 |
| `GET /api/v1/users` | 用户列表：`[{name, enabled, uplink_bytes, downlink_bytes}]` |
| `POST /api/v1/users` | 添加用户，请求体 `{"name": "...", "password": "..."}` → `201` |
| `GET /api/v1/users/:name` | 单个用户，含总上行/下行字节数 |
| `PUT /api/v1/users/:name/enabled` | 启用/暂停，请求体 `{"enabled": false}`（也接受 POST） |
| `PUT /api/v1/users/:name/password` | 修改密码，请求体 `{"password": "..."}`。PSK 即刻轮换：旧密码的新握手失败，已建立会话不受影响。 |
| `DELETE /api/v1/users/:name` | 删除用户 → `204` |

需要了解的语义：

- 用户与节点状态变更先经过完整的服务端配置校验，再**回写配置文件**（临时文件 + 原子 rename，保持键序与文件权限），重启后不丢失。会让配置变成非法状态的变更（比如删掉最后一个用户）会被拒绝，内存与磁盘都不变。
- 暂停/删除用户、修改密码、停用节点都只影响新握手；已建立的会话自然跑到结束（不做强制踢线）。进程级的 start/stop 刻意不在 API 里——进程停了就再没有东西能把它启起来，那是 systemd 的职责。
- `uplink_bytes` 是客户端发往目标方向的字节数，`downlink_bytes` 相反（服务端隧道载荷口径；UoT 含 9/21 字节封装头）。计数器在内存中，重启归零——`uptime_secs` 可供中控发现重置。
- API 是明文 HTTP + Bearer 令牌，刻意不带 TLS。`listen` 请保持回环，通过 SSH 隧道（`ssh -L 9090:127.0.0.1:9090`）或受信管理网访问；绑非回环地址时令牌强制 ≥32 字符并在启动时告警。路径中的用户名会做 percent 解码，含特殊字符的名字同样可以寻址。

### 日志级别

`trace` / `debug` / `info` / `warn` / `error`。优先级：`log.level` → 环境变量 `RUST_LOG` → 默认 `info`。

### 路由

sing-box 风格规则，按顺序评估，首个匹配生效。规则的 `inbound` 列表包含入站 `tag`，且 `auth_user` 列表（存在时）包含已认证用户名时匹配。不写 `auth_user` 的规则是该入站下所有未匹配用户的兜底规则。无规则匹配时，使用第一个出站（`outbounds[0]`）作为确定性回退。

客户端运行时目前仅支持单一出站——所有路由规则的 `outbound` 必须指向 `outbounds[0].tag`。服务端支持多出站，规则可引用任意已配置的出站 tag。`auth_user` 仅在服务端有意义（客户端入站没有认证用户）。

### 协议别名

客户端入站 `protocol` 字段接受 `"socks"` 作为 `"socks5"` 的别名。

### Session 调优

`idle_timeout_secs` 在服务端控制 session 空闲拆除（默认 75 秒，常量、无抖动）。配置验证接受 `[1, 3600]` 区间。客户端侧的连接空闲生命周期由连接池全权接管（115 秒空闲排干 + 3600 秒 soft TTL 兜底），此字段在客户端侧接受但不生效。服务端侧不做 clamp。

**服务端**空闲拆除机制：Session 读取循环使用 pin-reset 空闲定时器（默认 75 秒，常量、无抖动），每次成功读取时重置。定时器触发且无活跃流时，Session 优雅拆除（Noise 加密的 `close_notify` + TCP FIN）。不发送应用层心跳——内核 TCP keepalive 处理死端检测。

### 流量脚本

`traffic_script` 是一个**可选**的声明式程序，用于控制握手完成后应用数据记录的尺寸、时序和对端交互行为。省略时使用嵌入式默认脚本（6 条规则，即上文配置示例所示）。`session.max_streams_per_session`、`session.idle_timeout_secs` 和 `session.traffic_script` 均为可选字段——各字段适用于哪一侧请参见[字段参考](#字段参考)。`session.post_script_shaping` 选择脚本用尽后的行为：默认 `"markov"` 经融合窗口过渡到 Markov 机；`"off"` 完全关闭脚本后整形（记录按积压载荷的精确尺寸发出，零延迟、无 FakeResponse）。

脚本是一个 JSON 字符串数组：一个可选的 `stop=N` 控制条目（至多一个；省略时等于规则数）后跟带编号的规则 `i=L:...,D:...,F:...`，索引 `i` 必须与规则的 0 基位置一致（0、1、2……）。token 周围的空白会被容忍；每个条目都必须非空且格式正确。规则按 `packet_seq % 规则数` 循环应用，直到 `packet_seq` 达到 `stop`（`stop` 大于规则数即重复规则），随后在 6 包窗口内平滑过渡至 Markov 整形机（参见 docs/MECHANISM.zh-CN.md §3.5）。每条规则包含三个字段：

| 字段 | 格式 | 含义 |
|-------|--------|---------|
| `L` | `lo-hi` \| `n` \| `base?range` | 本条记录的应用内容字节数，从 `[lo, hi]` 区间均匀采样。整形器填充（或切分）至对应线速尺寸，使线速尺寸与真实载荷尺寸解耦。要求 `lo` ≤ `hi`。单个 `n` 为固定尺寸；`base?range` 在每条连接建立时采样一次 `base + U[0, range]` 并在该连接生命周期内固定。**必填。** |
| `D` | `0` \| `mu-sigma` \| `n` | 记录间停顿。`0` = 无延迟；`mu-sigma` = 对数正态分布，参数单位毫秒；单个数字 `n` = `ln(n)-0.5` 的简写。 |
| `F` | `0` \| `n` \| `n?k` | 若 `n > 0`，发送方排队一个 `CMD_PADDING` 请求，对端回复相应数量的非对称掩护帧（打破请求/响应对称性）。`0` 表示禁用。可选的 `?k` 为 fake 的落点加抖动：从 `[min(0,k), max(0,k)]` 区间内相对触发记录均匀采样一个偏移——负值在本条记录**之前**发出（归于前一条记录的槽位），零固定于本条记录，正值延后到之后的某条记录。 |

示例：

```json
"traffic_script": [
  "stop=7",
  "0=L:80-140,D:0,F:0",
  "1=L:200-350,D:0,F:1",
  "2=L:1200-4000,D:0,F:0",
  "3=L:80-120,D:0,F:1?2"
]
```

解读：握手后的前 7 条数据记录循环应用规则 0–3（`packet_seq % 4`）。记录尺寸从各规则的 `L` 窗口采样；规则 1 和规则 3 各触发一次掩护帧交换，其中规则 3 的 fake 可落在触发记录到其后第二条记录之间的任意位置。第 8 条记录起整形器平滑过渡至 Markov 机。

格式错误的脚本为非致命错误：启动时记录警告并整体回退至嵌入式默认脚本。

### TLS 配置

外层 TLS ClientHello 由捕获的 Firefox 模板生成（`fingerprint` 唯一取值，亦为默认值）。端点认证和载荷加密完全由 `Noise_NNpsk0` 与配置的 `password` 提供，外层 TLS 仅提供伪装。服务端使用缓存的参考端点 profile 完成可见 record 回放；`template_path` 可用捕获的 hex 文件覆盖内嵌 Firefox 模板。所有模板（内嵌或自定义）在加载时不剥离任何扩展；逐连接刷新 key_share 与 ECH GREASE 的变量字段（详见 [MECHANISM §6](docs/MECHANISM.zh-CN.md#6-指纹预设)）。

### TLS 指纹预设

| 值 | 来源 | 加密套件顺序 | Key Share 组 |
|---|------|-------------|-------------|
| `firefox` | 捕获的 bootstrap | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519MLKEM768, X25519, SECP256R1 |

`firefox` 是唯一受支持的取值，亦为默认值。其他取值在配置校验时直接报错。

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
- **Soft TTL 轮换**：3600 秒（对齐 nginx `keepalive_time` 默认值），连接转入排干状态
- **空闲排干**：115 秒无活跃 stream（对齐 Firefox `network.http.keep-alive.timeout`）→ 连接关闭
- **按需扩容**：仅在有等待者时创建新连接（常态为单连接，与真实 Firefox 对同一 origin 只开一条 H2 连接一致）
- **负载感知选择**：按 stream 数和缓冲流量选择连接

### 空闲拆除（服务端）

Session 读取循环（仅服务端；客户端由连接池管理）使用 pinned `tokio::time::sleep` 定时器，每次成功读取时重置。空闲超时 tick 时，session 检查是否存在活跃流；若无活跃流，则发送 Noise 加密的 TLS `close_notify`（0x15）和 TCP FIN，优雅拆除连接。内核 TCP keepalive 对齐 Firefox 默认值（空闲 600 秒、间隔 1 秒、4 次探测）作为死端检测。

## 吞吐调优

**架构事实**：全部流量复用在（常态下）一条隧道 TCP 连接上——这是防指纹设计的一部分（真实 Firefox 对同一 origin 只开一条 H2 连接）。因此总吞吐 = 单条 TCP 流在两端主机之间的吞吐，内核参数直接决定上限。

**高 BDP 路径（如 500 Mbps × 175 ms ⇒ BDP ≈ 10.9 MB）需要的宿主机配置**（客户端与服务端两侧都要）：

```bash
# /etc/sysctl.d/99-kanotls-bdp.conf
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432
```

kanotls 在建连时会主动请求 16 MiB 的 socket 缓冲（仅当 `net.core.*_max` 允许，否则保持内核自动调优并打出 warn 日志）。自动调优的封顶由 `net.ipv4.tcp_*mem` 的第三列决定（常见默认 4/6 MiB ⇒ 单连接约 180–270 Mbps 封顶）；不改内核参数，任何应用层优化都越不过这道墙。

**吞吐不达预期时的定位步骤**（三类瓶颈对号入座）：

1. 把 `log.level` 设为 `debug`，复现慢速场景，然后看三条日志：
   - `tunnel socket buffer via setsockopt` / `net.core.* too small` —— **内核缓冲不足**：按上面的 sysctl 调整；调完应看到 `effective ~16 MiB`。
   - `session flow-control summary: N send-side stalls, M ms total` —— **窗口停等**：stall 总时长占比高说明隧道内流控在限流（对端消费慢或路径 BDP 超窗口配置）。
   - `session writer data plane: bulk X records/Y bytes, shaped U records/V bytes` —— **CPU/记录开销**：shaped（小记录）字节占比异常高说明流量形态被误判成交互式，每字节加密开销约为满载态的 20 倍，弱 CPU 会因此限流。
2. 用 `post_script_shaping = "off"` 做 A/B 对照：off 下恢复满速 ⇒ 瓶颈在整形路径（CPU）；off 下仍慢 ⇒ 瓶颈在内核缓冲或路径本身（丢包/排队）。

注意：单条 TCP 流在高 BDP 路径上对丢包极其敏感（一次丢包的 cwnd 恢复在 175 ms RTT 下以分钟计），实验室 netem 环境请勿叠加非预期的丢包率。

## 伪装端点缓存

1. **启动**：从参考端点采集 4 次完整 flight，按 ClientHello 指纹 key 缓存（LRU，1024 条目，每 key 4 变体）。
2. **逐连接回放**：缓存的 ServerHello（session_id 回显，random 随机替换）、可见握手 record、0x17 记录合成回放。Noise 应答作为 0x17 记录注入，大小匹配首个缓存的 app_data 大小。
3. **后台刷新**：每个 (host, port) 守护进程每 300–3000 秒（随机化）刷新。

`reference` 可作为 `camouflage` 的别名。参考端点必须支持 TLS 1.3。阻止地址：private、loopback、link-local、multicast、unspecified、CGNAT。

### Pre-Auth 回落

提交到认证隧道路径之前的**每一种**失败，都会把客户端流量透明转发到伪装端点——非 TLS 首记录、认证失败、SNI 不匹配、记录头声明长度超限、记录截断/挂起，乃至什么都没发。交给转发的缓冲只含客户端真实发送过的字节；初始记录截止时间是两个固定常量（零字节 2 秒 / 已收到部分 5 秒）——刻意不随机化，因为真实 nginx 的 `client_header_timeout` 就是精确常量。因此探测者无法用任何构造出的输入得到不同的可观测结果。

转发受以下限额约束：

| 限制 | 值 |
|---|---|
| 全局并发回落 | 512（固定值） |
| 每 IP 并发回落 | 16（固定值） |
| 回落连接超时 | 3 秒（固定值） |
| 并发握手中连接数 | 512（固定值） |

限额耗尽时连接无法转发，统一走唯一出口：先排空接收队列（使关闭恒为干净 FIN 而非 RST），随后**立即关闭**——真实 nginx 在 `worker_connections` 耗尽时给出的正是 accept 后立即关闭。这是唯一不抵达伪装端点的路径；**单条连接的内容无法触发它**，但探测者可通过持有 16 条并发回落连接占满单 IP 限额来抵达。详见 [MECHANISM §5.2](docs/MECHANISM.zh-CN.md#52-pre-auth-回落)。

### 服务端出站

服务端出站定义中继流量的出口路径。支持两种协议：

| 协议 | 说明 | 配置项 |
|------|------|--------|
| `direct` | 直接 TCP/UDP 中继到目标 | _(无)_ |
| `socks5` | 通过上游 SOCKS5 代理中继 | `address`（主机）、`port`（1–65535）、可选 `username`/`password`（RFC 1929 认证） |

两种协议均支持 TCP CONNECT 和 UDP ASSOCIATE。路由引擎通过 `routing.rules` 中的 `inbound`（可选叠加认证用户）→ `outbound` 匹选出站。当无规则匹配时，使用第一个出站（`outbounds[0]`）作为确定性回退。

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

路由规则选择出站，可按认证用户分流：

```jsonc
"routing": {
  "rules": [
    {
      "inbound": ["tls-in"],
      "auth_user": ["1", "2"],
      "outbound": "socks5-out"
    },
    {
      "inbound": ["tls-in"],
      "outbound": "direct"
    }
  ]
}
```

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
| `routing.rules` | 双方 | sing-box 风格路由规则 |
| `api.listen` | 服务端 | 可选。管理 API 监听地址（见「管理 API」一节；缺省即关闭） |
| `api.token` | 服务端 | 可选。管理 API 的 Bearer 令牌（最少 16 字符；非回环监听时最少 32 字符） |

每条路由规则：

| 字段 | 说明 |
|------|------|
| `inbound` | 该规则适用的入站 tag 列表（必填） |
| `auth_user` | 可选。已认证用户名列表；省略时匹配该入站所有未命中其他规则的用户 |
| `outbound` | 规则命中时选择的出站 tag（必填） |

### 入站字段

| 字段 | 角色 | 说明 |
|------|------|------|
| `tag` | 双方 | 路由标签 |
| `listen` | 双方 | 监听地址（客户端：必须为 loopback IP 字面量） |
| `port` | 双方 | 监听端口 |
| `protocol` | 服务端 | `"kanotls"` |
| `enabled` | 服务端 | 可选（默认 `true`）。`false` 停用代理服务：所有连接回落到伪装站点。由管理 API 写入 |
| `protocol` | 客户端 | `"socks5"` / `"socks"` / `"http"` |
| `settings.users` | 服务端 | 用户列表 `[{name, password, enabled?}]`；用户名与密码均须唯一，密码最少 32 字节；`enabled` 默认 `true`（暂停时由管理 API 写入） |
| `settings.camouflage.host` | 服务端 | 参考 TLS 1.3 端点主机名（DNS 名称；不接受 IP 字面量） |
| `settings.camouflage.port` | 服务端 | 参考端点端口 |
| `settings.session.max_streams_per_session` | 双方 | 可选。单 session 最大并发 stream 数（默认 256） |
| `settings.session.idle_timeout_secs`       | 服务端 | 可选。session 空闲超时秒数（默认 45） |
| `settings.session.traffic_script`          | 双方 | 可选。声明式流量脚本（参见 docs/MECHANISM.zh-CN.md §3.5 及上文「流量脚本」章节） |
| `settings.session.post_script_shaping`     | 双方 | 可选。脚本后整形：`"markov"`（默认）或 `"off"`（脚本用尽后按精确尺寸、零延迟发出） |

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
| `protocol` | 必须为 `"kanotls"` |
| `settings.server` | 服务端地址 |
| `settings.port` | 服务端端口 |
| `settings.password` | 服务端某个用户的预共享密钥（最少 32 字节） |
| `settings.tls.sni` | 外层 ClientHello SNI（DNS 名称；不接受 IP 字面量） |
| `settings.tls.insecure` | 可选，当前忽略（默认 `false`）。外层 TLS 握手为回放式伪装，不发生证书验证；Noise 提供端点认证。 |
| `settings.tls.fingerprint` | 可选。仅 `firefox`（默认）；其他取值直接报配置错误 |
| `settings.tls.template_path` | 可选。捕获的 ClientHello hex 文件路径；覆盖内嵌 Firefox 模板（同样经过规范化）。每 30 秒 mtime 轮询热重载。 |
| `settings.session.idle_timeout_secs` | 可选。session 空闲超时（默认 45，服务端生效；客户端侧由连接池管理） |
| `settings.session.max_streams_per_session` | 可选。单 session 最大并发 stream 数（默认 256，验证至 [1, 4096]） |
| `settings.session.traffic_script` | 可选。声明式流量脚本（参见 docs/MECHANISM.zh-CN.md §3.5 及上文「流量脚本」章节） |
| `settings.session.post_script_shaping` | 可选。脚本后整形：`"markov"`（默认）或 `"off"` |

## 握手序列

```
客户端                                    服务端                         参考 TLS 端点
  |                                         |                                   |
  |--- ClientHello (0x16) ----------------->|                                   |
  |   Noise e 在 random; tag/counter/MAC    |--- ClientHello ------------------>|
  |   在 session_id; 独立 ks                 |<-- ServerHello + flight ----------|
  |                                         |                                   |
  |<-- ServerHello (0x16) ------------------|  (session_id 回显, random 替换)    |
  |<-- 前缀 0x17 (可选) ---------------------|  (逐连接新鲜 CSPRNG)                |
  |<-- Noise 应答 (0x17) --------------------|  (e, ee + KTL1 + ghost_count)     |
  |<-- 幽灵 0x17 × N ------------------------|  (逐连接新鲜 CSPRNG)                |
  |                                         |                                   |
  |--- CCS (6 B 明文) ---------------------->|  (0x14 记录，未加密)                |
  |--- Finished 幽灵 (0x17, 58 B) ---------->|  (Noise 加密于 0x17)               |
  |--- H2 SETTINGS 幽灵 (0x17) ------------->|  (65–77 B 明文变体)                |
  |                                         |                                   |
  |<====== Noise transport (0x17) =========>|  整形: TrafficShaper 决定 / ctrl HTTP/2 模拟尺寸|
```

## 许可证

GPL-3.0-or-later
