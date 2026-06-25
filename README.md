# kanotls

Experimental TLS + Noise tunnel for transport protocol research.

中文文档: [README.zh-CN.md](README.zh-CN.md) | Mechanisms: [docs/MECHANISM.md](docs/MECHANISM.md)

## Architecture

```
Application:   SOCKS5 / HTTP CONNECT proxy
Session:       Multiplexed streams + single-flush stream open + bimodal TLS record dispatch
Transport:     Noise_NNpsk0 (X25519 + ChaChaPoly + BLAKE2s) inside TLS 1.3 records
Outer TLS:     ClientHello presets (firefox / rustls / python-openssl)
               + cached reference endpoint record mirroring
UDP:           SOCKS5 UDP ASSOCIATE carried as UDP-over-TCP stream data
```

kanotls uses a separate Noise channel for endpoint authentication and payload confidentiality. The Noise ephemeral public key is embedded in the ClientHello `random` field via PSK-derived XOR masking; the `key_share` extension carries an **independent** TLS-layer X25519 ephemeral key to complete the visible handshake with the reference endpoint, eliminating statistical correlation between the two fields. The server replays cached reference-endpoint record shapes — it contacts the live camouflage endpoint only on first boot and during periodic background refresh.

Authentication and replay failures are handled by a shaped path with bounded pre-auth fallback for well-formed requests. Read-stage (post-authentication) failures fail closed without fallback. Fallback connections carry explicit abuse limits (concurrency caps, per-IP limits, connect timeouts, IP reputation cooldown). AEAD decryption failures emit a `bad_record_mac` fatal alert and trigger TCP RST — they never leak a clean `close_notify`.

Detailed mechanism reference: [docs/MECHANISM.md](docs/MECHANISM.md)

## Features

- **Multiplexed sessions**: Multiple logical streams share one outer TLS tunnel, with per-stream backpressure and bounded buffering.
- **Pipelined stream open**: Client fuses `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` into a single coalesced write flush before waiting for SYNACK. The server defers SYNACK until the relay connection to the target is established, so SYNACK confirms actual reachability rather than mere stream acceptance.
- **UDP-over-TCP**: SOCKS5 UDP datagrams framed over a session stream with address preservation.
- **XOR-based key hiding**: Noise ephemeral key XOR-masked into ClientHello `random`. Deterministic, stateless, avoids curve-point encoding bias.
- **Per-session counter anti-replay**: 40-bit random session identifier with 24-bit strictly monotonic sequence. Server uses a 64-bit sliding-window bitmap per session namespace (LRU, 4096 entries) plus a 600 s ephemeral-key replay cache (65536 entries) for defense in depth.
- **Per-session ephemeral key agreement**: Ephemeral X25519 key exchange per session with pre-shared key authentication (minimum 32 bytes). Each session uses a fresh Noise ephemeral key; compromise of one session key does not affect others.
- **HTTP CONNECT only**: HTTP inbound accepts only authority-form `CONNECT host:port`.
- **Destination guardrails**: Server rejects loopback, private, link-local, multicast, broadcast, unspecified, CGNAT, reserved (`240.0.0.0/4`), and port-0 destinations.
- **Single binary**: `cargo build --release`. Mode auto-detected from inbound protocol types.
- **TLS fingerprint presets**: `firefox`, `rustls`, `python-openssl` (alias `baseline`). Default `firefox`. Custom ClientHello hex via `template_path`.
- **Idle teardown**: Pin-reset idle timer per session; resets on each successful read. Idle timeout (default 45 s) triggers graceful session teardown with Noise-encrypted `close_notify` and TCP FIN. No application-layer heartbeat — kernel TCP keepalive (60 s idle, 30 s interval, 3 retries on Linux) handles dead-peer detection.
- **Bimodal record sizing**: Full bulk blocks are exact 16406-byte records (16384 content + 1 inner content type + 16 AEAD tag + 5 header, matching real Firefox TLS 1.3). Tail records (< 16382 B) use jittered padding (80% ≤32 B via exponential distribution, 20% full-block fill) producing wire sizes from n+24 to 16406. Control frames use HTTP/2-mimicking discrete sizes (33-82 bytes) with occasional HEADERS-like continuous frames (274-824 B C2S, 124-424 B S2C) via state-aware sampler (handshake pool vs transport pool).
- **Template hot-reload**: `template_path` hex files are polled every 30 s for mtime changes. On update, the file is re-parsed, the template cache invalidated, and new connections pick up the fresh ClientHello without restart. Failed parses are logged but preserve the previous template.

## Quick Start

### Build

```bash
cargo build --release
```

Start with `kanotls --config config.json`. Role auto-detection: `"protocol": "tunnel"` inbound → server mode; `socks5` / `socks` / `http` inbound → client mode.

### Server

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
          "idle_timeout_secs": 300
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "direct"
    }
,
    // SOCKS5 upstream proxy outbound (see Server Outbounds section):
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

### Client

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
          "idle_timeout_secs": 60,
          "max_streams_per_session": 256
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

## One-Click Server Deployment (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/LYCaikano/kanotls/main/install.sh | sudo bash
```

The script downloads the latest pre-built binary from GitHub Releases, installs it to `/usr/local/bin/kanotls`, creates `/etc/kanotls/` with a config skeleton, and installs the systemd unit.

The script is interactive — it presents a language selection (中文/English) and a menu (Install / Update / Uninstall). Install and Update offer a choice between stable and pre-release versions.

After installation, edit `/etc/kanotls/config.json`:
- Replace the placeholder password
- Set `camouflage.host` and `camouflage.port` to your reference endpoint

Then start the service:

```bash
sudo systemctl enable --now kanotls
sudo journalctl -u kanotls -f
```

The binary searches for its config at `/etc/kanotls/config.json` on Linux (or `/usr/local/etc/kanotls/config.json` on macOS), then falls back to the directory containing the executable. Use `--config` to specify a custom path.

## Configuration

### Password

Pre-shared key, identical on both sides. Minimum 32 bytes. Config validation rejects passwords containing placeholder substrings (`change_me`, `placeholder`, `replace_me`, `your_password_here`, `fill_me`). Generate:

```bash
openssl rand -base64 48
```

### Log Level

`trace` / `debug` / `info` / `warn` / `error`. Priority: `log.level` → `RUST_LOG` env → default `info`.

### Routing

Rules match by `inbounds[].tag`. The client runtime currently supports only a single outbound — all routing rules must resolve to `outbounds[0].tag`. The server supports multiple outbounds; rules may reference any configured outbound tag.

### Protocol Aliases

The client inbound `protocol` field accepts `"socks"` as an alias for `"socks5"`.

### Session Tuning

`idle_timeout_secs` on the client side is clamped to the range `[5, 3600]` at runtime (config validation accepts `[1, 3600]`). Server-side configuration is unclamped.

The session read loop uses a pin-reset idle timer (default 45 s) that resets on each successful read. When the timer fires and no streams are active, the session tears down gracefully. No application-layer heartbeat is sent — kernel TCP keepalive handles dead-peer detection.

The server pre-allocates an 8 MiB entropy pool (`ENTROPY_POOL`) at startup, used for ghost record payload generation during synthetic camouflage replay.

### TLS Configuration

The outer TLS ClientHello is generated per the `fingerprint` preset. `insecure` affects only the native-rustls generation path. Endpoint authentication and payload confidentiality come entirely from `Noise_NNpsk0` with the configured `password`. The server uses cached reference-endpoint profiles for visible record replay; `template_path` overrides the Firefox/Python-OpenSSL templates with a captured hex file (ignored by `rustls`).

### TLS Fingerprint Presets

| Value | Source | Cipher Suite Order | Key Share Groups |
|-------|--------|--------------------|------------------|
| `firefox` | Captured bootstrap | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519, SECP256R1 |
| `rustls` | Native rustls TLS 1.3 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | X25519, SECP256R1, SECP384R1 |
| `python-openssl` | Captured bootstrap | AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM | X25519, SECP256R1 |

`baseline` is an alias for `python-openssl`. Default: `firefox`.

### Custom ClientHello via `template_path`

Supply a captured hex file (`template_path`) to override the Firefox/Python-OpenSSL template. Files are **hot-reloaded** via mtime polling every 30 s — update the hex file and new connections pick up the fresh ClientHello without restarting the process. (Failed parses are logged but preserve the previous template.)

```json
"tls": {
  "sni": "example.com",
  "fingerprint": "firefox",
  "template_path": "/etc/kanotls/firefox_client_hello.hex"
}
```

Capture with Wireshark (`tls.handshake.type == 1`), copy the ClientHello as a hex stream, and paste into a file. The parser strips whitespace, newlines, `0x` prefixes, and array brackets — a raw Wireshark paste works directly.

Validate captures before deployment:

```bash
python3 update_firefox_template.py --input firefox_client_hello.hex --check-only
```

## Handshake Authentication

The ClientHello maintains normal TLS record structure. Fields expected to be random in TLS 1.3 carry authenticated Noise data:

- **`random[0..32]`**: Noise initiator ephemeral X25519 pubkey, XOR-masked with a PSK-derived mask.
- **`key_share` (ext 0x0033, X25519 entry)**: Independent fresh X25519 key for the visible TLS handshake — unrelated to the Noise key.
- **`session_id[0..16]`**: Noise PSK-authenticated AEAD tag from the first Noise message.
- **`session_id[16..24]`**: Connection counter, XOR-masked.
- **`session_id[24..32]`**: PSK-derived MAC over the counter and `random` prefix; low 2 bits of byte 31 cleared.

The server XOR-unmasks, validates the Noise tag and counter MAC, checks counter monotonicity per session via sliding window, and rejects replayed ephemeral keys via the replay cache.

## Session Multiplexing

### Frame Protocol

7-byte header: `| cmd (1) | stream_id (4, BE) | data_len (2, BE) | payload (…) |`

| Command | Opcode | Purpose |
|---|---|---|
| SYN | 0x01 | Open stream |
| PSH | 0x02 | Push data |
| FIN | 0x03 | Close stream |
| SETTINGS | 0x04 | Session capability negotiation |
| SYNACK | 0x07 | Stream open acknowledgment |

Max payload per frame: 65535 bytes. Adjacent frames are coalesced within the limit, then encrypted as TLS records.

### Pipelined Stream Open

Client fuses `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` into one coalesced flush before waiting for SYNACK. The first stream in a session defers its SYN until the first `write()` call, at which point SETTINGS + SYN + target + data are packed into a single coalesced write. The server defers SYNACK until the relay connection to the target is established.

### Connection Pool (Client)

- **Target pool size**: 4–16 concurrent connections, seeded by fingerprint family, SNI, and time-of-day
- **Staggered startup**: Initial connections spawn with jittered delays (50–2500 ms)
- **Soft TTL rotation**: After 120–300 s (seeded), connections stop accepting new streams
- **Idle drain**: 30 s idle with no active streams → connection closed
- **Demand-driven scaling**: New connections spawn only when waiters exist
- **Load-aware selection**: Connections chosen by stream count and buffered-traffic bytes

### Idle Teardown

Session read loop uses a pinned `tokio::time::sleep` timer that resets on each successful read. On idle timeout tick (default 45 s), the session checks whether any streams are active; if idle, it sends a Noise-encrypted TLS `close_notify` (0x15) and TCP FIN, tearing down the connection gracefully. No CMD_PING heartbeat is sent at the application layer — kernel TCP keepalive (60 s idle, 30 s interval, 3 retries on Linux) serves as the dead-peer detection mechanism instead.

## Camouflage Endpoint Caching

1. **Startup**: 4 flight samples from the reference endpoint, cached per ClientHello-fingerprint key (LRU, 1024 entries, 4 variants per key).
2. **Per-connection replay**: Cached ServerHello (session_id echoed, random randomized), visible handshake records, and 0x17 records replayed synthetically. Noise response injected as a 0x17 record matching the first cached app_data size.
3. **Background refresh**: Daemon per (host, port) refreshes every 300–3000 s (randomized).

`reference` is accepted as an alias for `camouflage`. The reference endpoint must support TLS 1.3. Blocked destinations: private, loopback, link-local, multicast, unspecified, and CGNAT addresses.

### Pre-Auth Fallback

Before committing to the authenticated tunnel path, certain failures can fall back to a bounded transparent relay to the camouflage endpoint:

| Limit | Value |
|---|---|
| Global concurrent fallbacks | 384–768 (randomized at startup) |
| Per-IP concurrent fallbacks | 12–24 (randomized) |
| Fallback connect timeout | 2–5 s (randomized) |
| IP cooldown threshold | 75–150 fallbacks per 3000–4200 s window → 240–420 s cooldown |

Fail-closed failures (read-stage errors, oversized records) never fall back.

### Server Outbounds

Server outbounds define the exit path for relayed traffic. Two protocols are supported:

| Protocol | Description | Settings |
|----------|-------------|----------|
| `direct` | Direct TCP/UDP relay to the target | _(none)_ |
| `socks5` | Relay through an upstream SOCKS5 proxy | `address` (host), `port` (1–65535), optional `username`/`password` (RFC 1929 auth) |

Both protocols support TCP CONNECT and UDP ASSOCIATE. The routing engine selects an outbound by matching `inbounds[].tag` → `outbound_tag` in `routing.rules`. When no rule matches, the first outbound (`outbounds[0]`) is used as the deterministic fallback.

Example SOCKS5 outbound:

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

Routing rules select the outbound:

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

### Fallback Tuning (`camouflage.fallback`)

The server config accepts an optional `camouflage.fallback` object (all fields have defaults):

| Field | Default | Description |
|-------|---------|-------------|
| `max_global` | 512 | Max total concurrent connections |
| `max_per_ip` | 16 | Max concurrent connections per IP |
| `min_lifetime_secs` | 30 | Min connection lifetime (s) |
| `max_lifetime_secs` | 3600 | Max connection lifetime (s) |
| `cooldown_duration_secs` | 300 | Cooldown after rate-limit (s) |
| `connect_timeout_secs` | 3 | Connection timeout (s) |

> **Note**: These fields are accepted during config parsing but are **not yet wired** into the runtime. Actual pre-auth fallback limits are randomized at startup from fixed ranges (see Pre-Auth Fallback table above).

## Constraint Invariants

| Constraint | Value |
|---|---|
| Noise protocol | `NNpsk0_25519_ChaChaPoly_BLAKE2s` |
| PSK minimum length | 32 bytes |
| Max concurrent handshakes | 512 |
| Max active sessions | 4096 |
| Counter sliding window | 64-bit bitmap (tolerates up to 63 behind) |
| Replay cache | 65536 entries, 600 s retention |
| ServerHello downgrade sentinel | Last 8 bytes preserved |

## Config Reference

### Top-level fields

| Field | Role | Description |
|-------|------|-------------|
| `log.level` | both | `trace` / `debug` / `info` / `warn` / `error` (default `info`) |
| `routing.rules` | both | sing-box-style inbound-tag routing |

### Inbound fields (server)

| Field                                      | Role   | Description                          |
| --------------------------------------------| --------| --------------------------------------|
| `tag`                                      | both   | Routing label                        |
| `listen`                                   | both   | Bind address (client: must be loopback IP literal) |
| `port`                                     | both   | Bind port                            |
| `protocol`                                 | server | `"tunnel"`                           |
| `protocol`                                 | client | `"socks5"` / `"socks"` / `"http"`    |
| `settings.password`                        | server | Pre-shared key, min 32 bytes         |
| `settings.camouflage.host`                 | server | Reference TLS 1.3 endpoint hostname (DNS name; IP literals rejected) |
| `settings.camouflage.port`                 | server | Reference endpoint port              |
| `settings.camouflage.fallback`             | server | Pre-auth fallback tuning (see below) |
| `settings.session.max_streams_per_session` | both   | Max streams per tunnel (default 256) |
| `settings.session.idle_timeout_secs`       | both   | Session idle timeout (default 45)    |

### Outbound fields (server)

| Field               | Protocol   | Description                                                    |
|----------------------|------------|----------------------------------------------------------------|
| `tag`                | both       | Routing label                                                  |
| `protocol`           | both       | `"direct"` or `"socks5"`                                       |
| `settings.address`   | `socks5`   | Upstream SOCKS5 proxy host (IP or hostname)                    |
| `settings.port`      | `socks5`   | Upstream SOCKS5 proxy port (1–65535)                           |
| `settings.username`  | `socks5`   | Optional RFC 1929 username (omit if empty)                     |
| `settings.password`  | `socks5`   | Optional RFC 1929 password (requires username; omit if empty)  |

### Outbound fields (client)

| Field                                      | Description                                                                                         |
| --------------------------------------------| -----------------------------------------------------------------------------------------------------|
| `tag`                                      | Routing tag                                                                                         |
| `protocol`                                 | Must be `"tunnel"`                                                                                  |
| `settings.server`                          | Server address                                                                                      |
| `settings.port`                            | Server port                                                                                         |
| `settings.password`                        | Pre-shared key                                                                                      |
| `settings.tls.sni`                         | ClientHello SNI (DNS name; IP literals rejected)                                                    |
| `settings.tls.insecure`                    | ClientHello-generation flag (default `false`)                                                       |
| `settings.tls.fingerprint`                 | Preset: `firefox` (default), `rustls`, `python-openssl`, `baseline`                                 |
| `settings.tls.template_path`               | Path to captured ClientHello hex file; overrides Firefox/Python-OpenSSL templates (ignored for `rustls`). Hot-reloaded via 30 s mtime polling. |
| `settings.session.idle_timeout_secs`       | Session idle timeout (default 45)                                                                   |
| `settings.session.max_streams_per_session` | Max streams per tunnel (default 256)                                                                |

## Handshake Sequence

```
Client                                 Server                       Reference Endpoint
  |                                      |                                    |
  |--- ClientHello (0x16) -------------->|                                    |
  |   Noise e in random; tag/counter/MAC |--- ClientHello ------------------->|
  |   in session_id; independent ks      |<-- ServerHello + flight -----------|
  |                                      |                                    |
  |<-- ServerHello (0x16) ---------------|  (session_id echoed, random replaced)
  |<-- Prefix 0x17 (optional) -----------|  (from entropy pool)
  |<-- Noise response (0x17) ------------|  (e, ee + KTL1 + ghost_count)
  |<-- Ghost 0x17 × N -------------------|  (fake ticket header + entropy)
  |                                      |                                    |
  |--- CCS (0x14) + Finished ghost ----->|  (Noise-encrypted in 0x17)
  |--- H2 SETTINGS ghost (0x17) -------->|  (65–77 B plaintext variant)
  |                                      |                                    |
  |<====== Noise transport (0x17) ======>|  bimodal: bulk 16406/exp-jittered tail / ctrl HTTP/2-mimicking
```

## License

GPL-3.0-or-later
