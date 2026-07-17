# kanotls

Experimental TLS + Noise tunnel for transport protocol research.

中文文档: [README.zh-CN.md](README.zh-CN.md) | Mechanisms: [docs/MECHANISM.md](docs/MECHANISM.md)

## Architecture

```
Application:   SOCKS5 / HTTP CONNECT proxy
Session:       Multiplexed streams + single-flush stream open + active traffic-shaped TLS record dispatch
Transport:     Noise_NNpsk0 (X25519 + ChaChaPoly + BLAKE2s) inside TLS 1.3 records
Outer TLS:     ClientHello presets (firefox / rustls / python-openssl)
               + cached reference endpoint record mirroring
UDP:           SOCKS5 UDP ASSOCIATE carried as UDP-over-TCP stream data
```

kanotls uses a separate Noise channel for endpoint authentication and payload confidentiality. The Noise ephemeral public key is embedded in the ClientHello `random` field via PSK-derived XOR masking; the `key_share` extension carries an **independent** TLS-layer X25519 ephemeral key to complete the visible handshake with the reference endpoint, eliminating statistical correlation between the two fields. The server replays cached reference-endpoint record shapes — it contacts the live camouflage endpoint only on first boot and during periodic background refresh.

Authentication and replay failures are handled by a shaped path with bounded pre-auth fallback for well-formed requests. Read-stage (post-authentication) failures fail closed without fallback. Fallback connections carry explicit abuse limits (concurrency caps, per-IP limits, connect timeouts, IP reputation cooldown). AEAD decryption failures silently close the connection — no alert is sent, no `close_notify` leaks.

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
- **Idle teardown**: Pin-reset idle timer per session; resets on each successful read. Idle timeout (default 45 s, configurable with ±10% jitter) triggers graceful session teardown with Noise-encrypted `close_notify` and TCP FIN. No application-layer heartbeat — kernel TCP keepalive (60 s idle, 30 s interval, 3 retries on Linux) handles dead-peer detection.
- **Active traffic shaping**: A full-lifecycle Markov state machine (TrafficShaper) actively slices, pads, and paces every application-data (0x17) record to shaper-dictated wire lengths — plaintext size never maps to wire size. Supports an optional declarative script (`traffic_script`) for deterministic control over post-handshake packet sequences, including inter-record Delay timing (log-normal or pre-recorded IAT replay) and asymmetric FakeResponse interactions (CMD_PADDING). All padding bytes are sourced from a shared 8 MiB CSPRNG-seeded noise pool, cryptographically isomorphic to genuine AEAD ciphertext.
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
          "idle_timeout_secs": 45,
          "traffic_script": "Length: 200~250, Delay: 0, FakeResponse: 0\nLength: 180~220, Delay: 1.5~0.6, FakeResponse: 0\nLength: 250~350, Delay: 0, FakeResponse: 1\nLength: 300~400, Delay: 2.0~0.5, FakeResponse: 0\nLength: 200~300, Delay: 0, FakeResponse: 1\nLength: 400~600, Delay: 3.0~0.7, FakeResponse: 0",
          "post_script_shaping": "markov" // optional
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "direct"
    },
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
          "max_streams_per_session": 256,
          "idle_timeout_secs": 45,
          "traffic_script": "Length: 200~250, Delay: 0, FakeResponse: 0\nLength: 180~220, Delay: 1.5~0.6, FakeResponse: 0\nLength: 250~350, Delay: 0, FakeResponse: 1\nLength: 300~400, Delay: 2.0~0.5, FakeResponse: 0\nLength: 200~300, Delay: 0, FakeResponse: 1\nLength: 400~600, Delay: 3.0~0.7, FakeResponse: 0",
          "post_script_shaping": "markov" // optional
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
curl -fsSL https://raw.githubusercontent.com/sparkfade/kanotls/main/install.sh | sudo bash
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

The session read loop uses a pin-reset idle timer (default 45 s, with ±10% jitter) that resets on each successful read. When the timer fires and no streams are active, the session tears down gracefully with a Noise-encrypted `close_notify` and TCP FIN. No application-layer heartbeat is sent — kernel TCP keepalive handles dead-peer detection.

Both server and client pre-allocate an 8 MiB entropy pool at startup, used for active record padding and camouflage ghost-record payload generation during synthetic replay.

### Traffic Script

`traffic_script` is an **optional** declarative program that controls the size, timing, and peer-interaction behavior of post-handshake application-data records. When omitted, an embedded default script (6 rules, shown in the config examples above) is used. `session.max_streams_per_session`, `session.idle_timeout_secs`, and `session.traffic_script` are all optional — see the [Config Reference](#config-reference) for which side each field applies to. `session.post_script_shaping` selects what happens once the script is exhausted: the default `"markov"` blends into the Markov machine, while `"off"` disables post-script shaping entirely (records are emitted at their exact pending size with zero delay and no fake responses).

The script is one rule per line; `#` comments and blank lines are ignored. Rules are applied cyclically via `packet_seq % rule_count` and, once exhausted, blend into the Markov shaping machine over a 6-packet window (see docs/MECHANISM.md §3.5). Each rule has three fields:

| Field | Format | Meaning |
|-------|--------|---------|
| `Length` | `lo~hi` | Application-content byte count for this record, sampled uniformly from `[lo, hi]`. The shaper pads (or splits) to the resulting wire size, decoupling wire size from real payload size. `lo` must be ≤ `hi`. **Required.** |
| `Delay` | `0` \| `mu~sigma` \| `n` | Inter-record pause. `0` = no delay; `mu~sigma` = log-normal distribution with parameters in milliseconds; a bare integer `n` = shorthand for `ln(n)~0.5`. |
| `FakeResponse` | integer | If `> 0`, after flushing this record the sender queues a `CMD_PADDING` request and the peer replies with that many asymmetric cover frames (breaks request/response symmetry). `0` disables it. |

Example (each `\n` is a literal newline inside the JSON string):

```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 300~400, Delay: 2.0~0.5, FakeResponse: 1
```

Malformed rules are non-fatal: a warning is logged at startup and the entire embedded default script is used as fallback.

### TLS Configuration

The outer TLS ClientHello is generated per the `fingerprint` preset. `insecure` (default `false`) disables TLS certificate verification in the native-rustls ClientHello generation path. Endpoint authentication and payload confidentiality come entirely from `Noise_NNpsk0` with the configured `password` — the outer TLS layer provides camouflage only. The server uses cached reference-endpoint profiles for visible record replay; `template_path` overrides the Firefox/Python-OpenSSL templates with a captured hex file (ignored by `rustls`).

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
| PADDING | 0x08 | Fake-response interaction engine |

Max payload per frame: 65535 bytes. Adjacent frames are coalesced within the limit, then encrypted as TLS records.

### Pipelined Stream Open

Client fuses `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` into one coalesced flush before waiting for SYNACK. The first stream in a session defers its SYN until the first `write()` call, at which point SETTINGS + SYN + target + data are packed into a single coalesced write. The server defers SYNACK until the relay connection to the target is established.

### Connection Pool (Client)

- **Target pool size**: Seeded from fingerprint family, SNI, and time-of-day (default 4–16)
- **Staggered startup**: Initial connections spawn with jittered delays (50–2500 ms)
- **Soft TTL rotation**: 120–300 s (seeded), connections stop accepting new streams
- **Idle drain**: 30 s idle with no active streams → connection closed
- **Demand-driven scaling**: New connections spawn only when waiters exist
- **Load-aware selection**: Connections chosen by stream count and buffered-traffic bytes

### Idle Teardown

Session read loop uses a pinned `tokio::time::sleep` timer that resets on each successful read. On idle timeout tick (default 45 s, configurable with ±10% jitter), the session checks whether any streams are active; if idle, it sends a Noise-encrypted TLS `close_notify` (0x15) and TCP FIN, tearing down the connection gracefully. No CMD_PING heartbeat is sent at the application layer — kernel TCP keepalive (60 s idle, 30 s interval, 3 retries on Linux) serves as the dead-peer detection mechanism instead.

## Camouflage Endpoint Caching

1. **Startup**: 4 flight samples from the reference endpoint, cached per ClientHello-fingerprint key (LRU, 1024 entries, 4 variants per key).
2. **Per-connection replay**: Cached ServerHello (session_id echoed, random randomized), visible handshake records, and 0x17 records replayed synthetically. Noise response injected as a 0x17 record matching the first cached app_data size.
3. **Background refresh**: Daemon per (host, port) refreshes every 300–3000 s (randomized).

`reference` is accepted as an alias for `camouflage`. The reference endpoint must support TLS 1.3. Blocked destinations: private, loopback, link-local, multicast, unspecified, and CGNAT addresses.

### Pre-Auth Fallback

Before committing to the authenticated tunnel path, certain failures can fall back to a bounded transparent relay to the camouflage endpoint:

| Limit | Value |
|---|---|
| Global concurrent fallbacks | 512 (fixed) |
| Per-IP concurrent fallbacks | 16 (fixed) |
| Fallback connect timeout | 3 s (fixed) |
| IP cooldown threshold | 112 fallbacks per 3600 s window → 300 s cooldown |

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

## Constraint Invariants

| Constraint | Value |
|---|---|
| Noise protocol | `NNpsk0_25519_ChaChaPoly_BLAKE2s` |
| PSK minimum length | 32 bytes |
| Max concurrent handshakes | 512 |
| Max active sessions | 4096 |
| Counter sliding window | 64-bit bitmap (tolerates up to 63 behind) |
| Replay cache | 65536 entries, 600 s retention |
| Max streams per session | 4096 (config validation) |

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
| `settings.session.max_streams_per_session` | both   | Optional. Max streams per tunnel (default 256) |
| `settings.session.idle_timeout_secs`       | both   | Optional. Session idle timeout (default 45)    |
| `settings.session.traffic_script`          | both   | Optional. Declarative traffic script (see docs/MECHANISM.md §3.5 and the Traffic Script section above) |
| `settings.session.post_script_shaping`     | both   | Optional. Post-script shaping: `"markov"` (default) or `"off"` (exact-size, zero-delay records once the script ends) |

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

| Field | Description |
|--------|----------------|
| `tag` | Routing tag |
| `protocol` | Must be `"tunnel"` |
| `settings.server` | Server address |
| `settings.port` | Server port |
| `settings.password` | Pre-shared key (min 32 bytes) |
| `settings.tls.sni` | ClientHello SNI (DNS name; IP literals rejected) |
| `settings.tls.insecure` | Optional. Skip TLS cert verification in rustls path (default `false`). Only affects the native-rustls ClientHello generation; Noise provides endpoint auth. |
| `settings.tls.fingerprint` | Optional. Preset: `firefox` (default), `rustls`, `python-openssl`, `baseline` |
| `settings.tls.template_path` | Optional. Path to captured ClientHello hex file; overrides Firefox/Python-OpenSSL templates (ignored for `rustls`). Hot-reloaded via 30 s mtime polling. |
| `settings.session.idle_timeout_secs` | Optional. Session idle timeout (default 45, clamped to [5,3600] client-side) |
| `settings.session.max_streams_per_session` | Optional. Max streams per tunnel (default 256, validated to [1,4096]) |
| `settings.session.traffic_script` | Optional. Declarative traffic script (see docs/MECHANISM.md §3.5 and the Traffic Script section above) |
| `settings.session.post_script_shaping` | Optional. Post-script shaping: `"markov"` (default) or `"off"` |

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
  |--- CCS (6 B plain) ----------------->|  (0x14 record, unencrypted)
  |--- Finished ghost (0x17, 58 B) ----->|  (Noise-encrypted in 0x17)
  |--- H2 SETTINGS ghost (0x17) -------->|  (65–77 B plaintext variant)
  |                                      |                                    |
  |<====== Noise transport (0x17) ======>|  shaped: TrafficShaper-dictated / control HTTP/2-mimicking
```

## License

GPL-3.0-or-later
