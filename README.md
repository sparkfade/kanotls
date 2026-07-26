# kanotls

Experimental TLS + Noise tunnel for transport protocol research.

中文文档: [README.zh-CN.md](README.zh-CN.md) | Mechanisms: [docs/MECHANISM.md](docs/MECHANISM.md)

## Architecture

```
Application:   SOCKS5 / HTTP CONNECT proxy
Session:       Multiplexed streams + single-flush stream open + active traffic-shaped TLS record dispatch
Transport:     Noise_NNpsk0 (X25519 + ChaChaPoly + BLAKE2s) inside TLS 1.3 records
Outer TLS:     ClientHello preset (firefox)
               + cached reference endpoint record mirroring
UDP:           SOCKS5 UDP ASSOCIATE carried as UDP-over-TCP stream data
```

kanotls uses a separate Noise channel for endpoint authentication and payload confidentiality. The Noise ephemeral public key is embedded in the ClientHello `random` field via PSK-derived XOR masking; the `key_share` extension carries an **independent** TLS-layer X25519 ephemeral key to complete the visible handshake with the reference endpoint, eliminating statistical correlation between the two fields. The server replays cached reference-endpoint record shapes — it contacts the live camouflage endpoint only on first boot and during periodic background refresh.

Authentication and replay failures are handled by a shaped path with bounded pre-auth fallback for well-formed requests. Read-stage (post-authentication) failures fail closed without fallback. Fallback connections carry explicit abuse limits (512 global concurrent, 16 per-IP concurrent, a 3 s connect timeout); the per-IP cumulative rate cooldown has been removed — it let 113 ordinary connections push an IP onto the non-forwarding branch, manufacturing a content-level, zero-false-positive discriminator. AEAD decryption failures silently close the connection — no alert is sent, no `close_notify` leaks.

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
- **TLS fingerprint**: `firefox` (captured bootstrap; the only preset). Custom ClientHello hex via `template_path`. **No extension is stripped** — the emitted extension-type list is item-for-item identical to the captured real Firefox (15 of them) and the ClientHello is 1884 bytes. Regenerated per connection: a structurally valid X25519MLKEM768 hybrid share, a real P-256 curve point, and **one** X25519 key written to both the 0x001d share and the hybrid share (real Firefox reuses the same key — NSS Bug 1902119), plus the ECH GREASE `config_id`/`enc`/`payload` fields.
- **Idle teardown**: Pin-reset idle timer per server session; resets on each successful read. Idle timeout (default **75 s**, configurable, a **constant with no jitter**, taken from nginx's `keepalive_timeout` default) triggers graceful session teardown with Noise-encrypted `close_notify` and TCP FIN. Client-side connection idle lifecycle is fully managed by the connection pool (**115 s** idle drain, matching Firefox's `network.http.keep-alive.timeout`; soft TTL **3600 s**, matching nginx's `keepalive_time` 1h default); `idle_timeout_secs` applies to the server side only. No application-layer heartbeat — kernel TCP keepalive matches Firefox's defaults (**600 s** idle, **1 s** interval, **4** probes, no jitter). At the H2 layer the client sends an idle PING (triggered after 58 s with no peer arrival, suppressed inside the observation window), and a GOAWAY precedes teardown.
- **Active traffic shaping**: A full-lifecycle Markov state machine (TrafficShaper) actively slices, pads, and paces every application-data (0x17) record to shaper-dictated wire lengths — plaintext size never maps to wire size. Supports an optional declarative script (`traffic_script`) for deterministic control over post-handshake packet sequences, including inter-record Delay timing (log-normal or pre-recorded IAT replay) and asymmetric FakeResponse interactions (CMD_PADDING). Record padding is zero, per RFC 8446 §5.4 — it sits on the plaintext side of the AEAD, so its content is invisible on the wire.
- **Template hot-reload**: `template_path` hex files are polled every 30 s for mtime changes. On update, the file is re-parsed, the template cache invalidated, and new connections pick up the fresh ClientHello without restart. Failed parses are logged but preserve the previous template.

## Quick Start

### Build

```bash
cargo build --release
```

Start with `kanotls --config config.json`. Role auto-detection: `"protocol": "kanotls"` inbound → server mode; `socks5` / `socks` / `http` inbound → client mode.

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
          "post_script_shaping": "markov" // optional
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

## One-Click Server Deployment (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/sparkfade/kanotls/main/install.sh | sudo bash
```

The script downloads the latest pre-built binary from GitHub Releases, installs it to `/usr/local/bin/kanotls`, creates `/etc/kanotls/` with a config skeleton, and installs the systemd unit.

The script is interactive — it presents a language selection (中文/English) and a menu (Install / Update / Uninstall). Install and Update offer a choice between stable and pre-release versions.

After installation, edit `/etc/kanotls/config.json`:
- Replace the placeholder password in `settings.users`
- Set `camouflage.host` and `camouflage.port` to your reference endpoint

Then start the service:

```bash
sudo systemctl enable --now kanotls
sudo journalctl -u kanotls -f
```

The binary searches for its config at `/etc/kanotls/config.json` on Linux (or `/usr/local/etc/kanotls/config.json` on macOS), then falls back to the directory containing the executable. Use `--config` to specify a custom path.

## Configuration

### Users

The server inbound authenticates clients against `settings.users`, a list of `{name, password}` entries. Each password is an independent pre-shared key (minimum 32 bytes); names and passwords must both be unique within an inbound. Config validation rejects passwords containing placeholder substrings (`change_me`, `placeholder`, `replace_me`, `your_password_here`, `fill_me`). Generate:

```bash
openssl rand -base64 48
```

The client outbound carries a single `settings.password` matching one of the server's user entries. The authenticated user name is attached to the connection and can be used for per-user routing via `auth_user`.

### Log Level

`trace` / `debug` / `info` / `warn` / `error`. Priority: `log.level` → `RUST_LOG` env → default `info`.

### Routing

sing-box-style rules, evaluated in order; the first match wins. A rule matches when its `inbound` list contains the inbound's `tag` and its `auth_user` list (when present) contains the authenticated user name. A rule without `auth_user` is a catch-all for every remaining user of that inbound. When no rule matches, the first outbound (`outbounds[0]`) is used as the deterministic fallback.

The client runtime currently supports only a single outbound — all routing rules must resolve to `outbounds[0].tag`. The server supports multiple outbounds; rules may reference any configured outbound tag. `auth_user` is only meaningful on the server (client inbounds have no authenticated users).

### Protocol Aliases

The client inbound `protocol` field accepts `"socks"` as an alias for `"socks5"`.

### Session Tuning

`idle_timeout_secs` controls server-side session idle teardown (default 75 s, a constant with no jitter). Config validation accepts `[1, 3600]`. The connection pool fully manages client-side connection idle lifecycle (115 s idle drain + a 3600 s soft-TTL backstop); this field is accepted but unused client-side. Server-side configuration is unclamped.

**Server-side** idle teardown: The session read loop uses a pin-reset idle timer (default 75 s, a constant with no jitter) that resets on each successful read. When the timer fires and no streams are active, the session tears down gracefully with a Noise-encrypted `close_notify` and TCP FIN. No application-layer heartbeat is sent — kernel TCP keepalive handles dead-peer detection.

### Traffic Script

`traffic_script` is an **optional** declarative program that controls the size, timing, and peer-interaction behavior of post-handshake application-data records. When omitted, an embedded default script (6 rules, shown in the config examples above) is used. `session.max_streams_per_session`, `session.idle_timeout_secs`, and `session.traffic_script` are all optional — see the [Config Reference](#config-reference) for which side each field applies to. `session.post_script_shaping` selects what happens once the script is exhausted: the default `"markov"` blends into the Markov machine, while `"off"` disables post-script shaping entirely (records are emitted at their exact pending size with zero delay and no fake responses).

The script is a JSON array of entries: an optional `stop=N` control entry (at most one; defaults to the rule count) followed by numbered rules `i=L:...,D:...,F:...` whose index `i` must match the rule's 0-based position (0, 1, 2, ...). Whitespace around tokens is tolerated; every entry must be non-empty and well-formed. Rules are applied cyclically via `packet_seq % rule_count` until `packet_seq` reaches `stop` (so `stop` larger than the rule count repeats the rules), then blend into the Markov shaping machine over a 6-packet window (see docs/MECHANISM.md §3.5). Each rule has three fields:

| Field | Format | Meaning |
|-------|--------|---------|
| `L` | `lo-hi` \| `n` \| `base?range` | Application-content byte count for this record, sampled uniformly from `[lo, hi]`. The shaper pads (or splits) to the resulting wire size, decoupling wire size from real payload size. `lo` must be ≤ `hi`. A bare `n` is a fixed size; `base?range` samples `base + U[0, range]` once per connection and keeps it fixed for that connection's lifetime. **Required.** |
| `D` | `0` \| `mu-sigma` \| `n` | Inter-record pause. `0` = no delay; `mu-sigma` = log-normal distribution with parameters in milliseconds; a bare number `n` = shorthand for `ln(n)-0.5`. |
| `F` | `0` \| `n` \| `n?k` | If `n > 0`, the sender queues a `CMD_PADDING` request and the peer replies with that many asymmetric cover frames (breaks request/response symmetry). `0` disables it. The optional `?k` jitters where the fake is emitted: an offset is sampled uniformly from `[min(0,k), max(0,k)]` records relative to the triggering record — negative emits *before* this record (the previous record's slot), zero pins it to this record, positive defers it to a later record. |

Example:

```json
"traffic_script": [
  "stop=7",
  "0=L:80-140,D:0,F:0",
  "1=L:200-350,D:0,F:1",
  "2=L:1200-4000,D:0,F:0",
  "3=L:80-120,D:0,F:1?2"
]
```

Reading it: the first 7 post-handshake data records cycle rules 0–3 (`packet_seq % 4`). Record sizes are drawn from each rule's `L` window; rule 1 and rule 3 additionally trigger one cover-frame exchange, rule 3's landing anywhere from the triggering record up to two records later. From the 8th record onward the shaper blends into the Markov machine.

Malformed scripts are non-fatal: a warning is logged at startup and the entire embedded default script is used as fallback.

### TLS Configuration

The outer TLS ClientHello is generated from the captured Firefox template (the only `fingerprint` value, and the default). Endpoint authentication and payload confidentiality come entirely from `Noise_NNpsk0` with the configured `password` — the outer TLS layer provides camouflage only. The server uses cached reference-endpoint profiles for visible record replay; `template_path` overrides the embedded Firefox template with a captured hex file. No extension is stripped from any template (embedded or custom); the key_share and ECH GREASE variable fields are refreshed per connection (see [MECHANISM §6](docs/MECHANISM.md#6-fingerprint-presets)).

### TLS Fingerprint Presets

| Value | Source | Cipher Suite Order | Key Share Groups |
|-------|--------|--------------------|------------------|
| `firefox` | Captured bootstrap | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519MLKEM768, X25519, SECP256R1 |

`firefox` is the only supported value and the default. Any other value fails config validation.

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

### Idle Teardown (Server)

The session read loop (server-side only; client sessions are lifecycle-managed by the connection pool) uses a pinned `tokio::time::sleep` timer that resets on each successful read. On idle timeout tick, the session checks whether any streams are active; if idle, it sends a Noise-encrypted TLS `close_notify` (0x15) and TCP FIN, tearing down the connection gracefully. Kernel TCP keepalive, matching Firefox's defaults (600 s idle, 1 s interval, 4 probes), serves as dead-peer detection.

## Camouflage Endpoint Caching

1. **Startup**: 4 flight samples from the reference endpoint, cached per ClientHello-fingerprint key (LRU, 1024 entries, 4 variants per key).
2. **Per-connection replay**: Cached ServerHello (session_id echoed, random randomized), visible handshake records, and 0x17 records replayed synthetically. Noise response injected as a 0x17 record matching the first cached app_data size.
3. **Background refresh**: Daemon per (host, port) refreshes every 300–3000 s (randomized).

`reference` is accepted as an alias for `camouflage`. The reference endpoint must support TLS 1.3. Blocked destinations: private, loopback, link-local, multicast, unspecified, and CGNAT addresses.

### Pre-Auth Fallback

**Every** failure before the authenticated tunnel path is committed relays the client's traffic transparently to the camouflage endpoint — non-TLS first record, auth failure, SNI mismatch, an oversized declared record length, a stalled/partial record, or nothing sent at all. The relayed buffer contains only bytes the client actually sent, and the initial-record deadline is two fixed constants (2 s for zero bytes, 5 s once a partial record exists) — deliberately not randomized, because a real nginx's `client_header_timeout` is itself an exact constant. No input a prober can construct produces a different observable.

Relaying is bounded:

| Limit | Value |
|---|---|
| Global concurrent fallbacks | 512 (fixed) |
| Per-IP concurrent fallbacks | 16 (fixed) |
| Fallback connect timeout | 3 s (fixed) |
| Concurrent in-handshake connections | 512 (fixed) |

When a limit is exhausted the connection cannot be relayed and takes a single unified exit: the receive queue is drained (so the close is always a clean FIN rather than an RST) and the socket is then closed **immediately** — which is exactly what a real nginx does when `worker_connections` is exhausted. This is the only path that does not reach the camouflage endpoint; **no single connection's content triggers it**, though a prober can reach it by holding 16 concurrent fallback connections to occupy the per-IP limit. See [MECHANISM §5.2](docs/MECHANISM.md#52-pre-auth-fallback).

### Server Outbounds

Server outbounds define the exit path for relayed traffic. Two protocols are supported:

| Protocol | Description | Settings |
|----------|-------------|----------|
| `direct` | Direct TCP/UDP relay to the target | _(none)_ |
| `socks5` | Relay through an upstream SOCKS5 proxy | `address` (host), `port` (1–65535), optional `username`/`password` (RFC 1929 auth) |

Both protocols support TCP CONNECT and UDP ASSOCIATE. The routing engine selects an outbound by matching `inbounds[].tag` (and optionally the authenticated user) → `outbound` in `routing.rules`. When no rule matches, the first outbound (`outbounds[0]`) is used as the deterministic fallback.

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

Routing rules select the outbound, optionally per authenticated user:

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
| `routing.rules` | both | sing-box-style routing rules |

Each routing rule:

| Field | Description |
|-------|-------------|
| `inbound` | List of inbound tags this rule applies to (required) |
| `auth_user` | Optional list of authenticated user names; omit to match all remaining users of the inbound |
| `outbound` | Tag of the outbound selected when the rule matches (required) |

### Inbound fields (server)

| Field                                      | Role   | Description                          |
| --------------------------------------------| --------| --------------------------------------|
| `tag`                                      | both   | Routing label                        |
| `listen`                                   | both   | Bind address (client: must be loopback IP literal) |
| `port`                                     | both   | Bind port                            |
| `protocol`                                 | server | `"kanotls"`                          |
| `protocol`                                 | client | `"socks5"` / `"socks"` / `"http"`    |
| `settings.users`                           | server | User list: `[{name, password}]`; names and passwords unique, password min 32 bytes |
| `settings.camouflage.host`                 | server | Reference TLS 1.3 endpoint hostname (DNS name; IP literals rejected) |
| `settings.camouflage.port`                 | server | Reference endpoint port              |
| `settings.session.max_streams_per_session` | both   | Optional. Max streams per tunnel (default 256) |
| `settings.session.idle_timeout_secs`       | server | Optional. Session idle timeout (default 45)    |
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
| `protocol` | Must be `"kanotls"` |
| `settings.server` | Server address |
| `settings.port` | Server port |
| `settings.password` | Pre-shared key of one server user (min 32 bytes) |
| `settings.tls.sni` | ClientHello SNI (DNS name; IP literals rejected) |
| `settings.tls.insecure` | Optional, currently ignored (default `false`). The outer TLS handshake is a replayed facade — no certificate verification occurs; Noise provides endpoint auth. |
| `settings.tls.fingerprint` | Optional. Only `firefox` (default); any other value is a config error |
| `settings.tls.template_path` | Optional. Path to captured ClientHello hex file; overrides the embedded Firefox template (same normalization applies). Hot-reloaded via 30 s mtime polling. |
| `settings.session.idle_timeout_secs` | Optional. Session idle timeout (default 45, server-side; client-side managed by connection pool) |
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
  |<-- ServerHello (0x16) ---------------|  (session_id echoed; random and key_share regenerated)
  |<-- Prefix 0x17 (optional) -----------|  (fresh CSPRNG, per connection)
  |<-- Noise response (0x17) ------------|  (e, ee + KTL1 + ghost_count)
  |<-- Ghost 0x17 × N -------------------|  (fresh CSPRNG, per connection)
  |                                      |                                    |
  |--- CCS (6 B plain) ----------------->|  (0x14 record, unencrypted)
  |--- Finished ghost (0x17, 58 B) ----->|  (Noise-encrypted in 0x17)
  |--- H2 SETTINGS ghost (0x17) -------->|  (65–77 B plaintext variant)
  |                                      |                                    |
  |<====== Noise transport (0x17) ======>|  shaped: TrafficShaper-dictated / control HTTP/2-mimicking
```

## License

GPL-3.0-or-later
