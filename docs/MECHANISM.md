# KanoTLS — Internal Mechanism Reference

This document describes the internal architecture, cryptographic design, and traffic-shaping logic of KanoTLS. It accompanies the main README; read that first for an overview.

---

## 1. Handshake Authentication Embedding

### 1.1 Noise in ClientHello Fields

The outer TLS ClientHello carries a full `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` initial handshake payload inside fields that are expected to be random in TLS 1.3:

| ClientHello field | Content | Size | Encoding |
|---|---|---|---|
| `random[0..32]` | Noise initiator ephemeral X25519 pubkey (`e`) | 32 B | XOR with `derive_noise_e_mask(derived_psk, noise_tag)` |
| `session_id[0..16]` | Noise PSK-authenticated AEAD tag | 16 B | Plain copy from `psk_e[32..48]` |
| `session_id[16..24]` | Connection counter | 8 B | XOR with `derive_counter_mask(derived_psk, random)` |
| `session_id[24..32]` | Counter authentication MAC | 8 B | `derive_counter_mac(psk, random, masked_counter, random[..16])`; low 2 bits of byte 31 cleared |
| `key_share` (ext 0x0033) | Independent TLS-layer X25519 ephemeral | 32 B | `rand::thread_rng().fill_bytes()` — unrelated to Noise key |

The mapping is deterministic: given the same PSK and Noise initiator state, the same ClientHello fields are produced. The server recovers the Noise ephemeral key by applying the same XOR mask, reconstructs the 48-byte Noise init message (32B `e` + 16B tag), and completes `NoiseState::read_message()`.

### 1.2 Why Dual Key Shares?

The `key_share` extension contains a fresh random X25519 public key per connection. This key completes the visible TLS handshake with the reference (camouflage) endpoint. It is **cryptographically independent** of the Noise key in `random`. This prevents a passive observer from correlating the two 32-byte fields via statistical tests — they are generated from separate entropy sources (`rand::thread_rng` vs `snow::Builder::build_initiator()`).

### 1.3 Counter Anti-Replay

The 64-bit counter is split:

```
counter = (session_id << 24) | sequence
```

- **session_id** (40 bits): Random per-client-restart identifier, isolating independent sessions.
- **sequence** (24 bits): Strictly monotonic per-session, starting at 1.

The server uses a **64-bit sliding-window bitmap** per session namespace (LRU-cached, 4096 entries). Sequences ahead of the highest seen advance the window; sequences up to 63 behind are checked against the bitmap; older sequences are rejected. The same sequence number is never accepted twice.

A separate **ephemeral-key replay cache** (LRU, 65536 entries, 600s TTL) catches full ClientHello replays by keying on the recovered Noise ephemeral public key.

---

## 2. Camouflage Profile System

### 2.1 Profile Structure

A `CamouflageProfile` records the visible TLS 1.3 handshake shape of the reference endpoint:

| Field | Description |
|---|---|
| `server_records` | Raw bytes of all visible handshake records (ServerHello, Certificate, CCS, etc.) |
| `prefix_app_data_sizes` | Wire-level sizes of early 0x17 records that are too small to carry Noise payload |
| `app_data_sizes` | Wire-level sizes of all sampled 0x17 records from the reference endpoint |
| `first_app_data_delay_ms` | Milliseconds between ServerHello completion and first 0x17 record |
| `early_app_data_gap_ms` | Inter-record gaps between consecutive 0x17 records |
| `has_ccs` | Whether the reference endpoint sent a CCS record |

### 2.2 Startup Health Check

On server boot, `validate_camouflage_endpoint()` sends a fresh rustls-generated ClientHello to the reference endpoint 4 times. Each flight is fingerprinted (random/session_id/key_share zeroed, padding extension normalized) and cached under both a per-fingerprint key and a fingerprint-family baseline key (first 8 hex chars of the fingerprint hash).

### 2.3 Per-Connection Replay

When a client connects:

1. ClientHello is fingerprinted via `stable_client_hello_fingerprint()`.
2. The server looks up the best cached profile (prefers complete profiles: rank 3 = has both server_records and app_data_sizes).
3. If no complete profile is cached, `fetch_camouflage_flight()` performs a live fetch to the reference endpoint (with refresh-gate deduplication).
4. `establish_synthetic_camouflage_tunnel()`:
   - Echoes the client's `session_id` into the cached ServerHello.
   - Replaces the ServerHello `random` with fresh bytes (preserving downgrade-sentinel if present).
   - Emits all visible handshake records.
   - Emits prefix 0x17 records (too small to carry Noise), filled from the `ENTROPY_POOL` (8 MiB of `rand::thread_rng()` bytes).
   - Emits the Noise response wrapped in a 0x17 record (sized to match the first cached app_data size, with the Noise server public key XOR-masked in the first 32 bytes).
   - Emits ghost 0x17 records (sized per cache), each prefixed with a 16-byte fake session-ticket structure header before entropy-pool fill, to reduce entropy fingerprinting.

### 2.4 Background Refresh

A daemon per (host, port) pair refreshes the profile every 300–3000 seconds (randomized), using the same ClientHello fingerprint as the probe.

---

## 3. Active Traffic Shaping

### 3.1 Design Rationale

The original bimodal distribution (§3.1–3.4 in v1.0) passively split application payloads at `BLOCK_DATA_CAPACITY` (16382) boundaries and applied probabilistic tail padding. This mapped the inner-TLS plaintext size directly onto the wire record length, exposing structural signatures (e.g., a 5000-byte certificate would produce 16382 + 16382 + 1236 = three records whose sizes leak the inner handshake shape). v1.1 replaces this with a **top-down active TrafficShaper** that dictates every record's on-wire length independently of the application payload — plaintext length never maps to wire length.

### 3.2 Control Class

Protocol frames (CMD_SYN, CMD_FIN, CMD_SETTINGS, CMD_SYNACK, CMD_PADDING) use `encrypt_variable_block(PadFill::Zero)`. Their wire sizes are determined by a **state-aware sampler** in `control_size`:

- **Handshake state** (first 6 control frames): 7 discrete sizes (33, 37, 46, 51, 64, 69, 82) mimicking HTTP/2 SETTINGS, SETTINGS_ACK, WINDOW_UPDATE, and merged variants. 5% of frames additionally sample from a truncated-normal HEADERS frame distribution (C2S: μ=450, σ=120, [250, 800]; S2C: μ=200, σ=50, [100, 400]).
- **Transport state** (6+ control frames): 5 discrete sizes (33, 37, 41, 46, 54) mimicking PING, WINDOW_UPDATE, SETTINGS_ACK, and merged variants (no SETTINGS sizes). 10% of frames sample from the same HEADERS frame distribution.

Each control record increments the TrafficShaper's internal control-frame counter (`note_control_frame()`), which governs the handshake-to-transport transition used by the shaper's Markov machine (§3.4).

### 3.3 TrafficShaper Architecture

The `TrafficShaper` (per-connection, owned by `SessionWriter::run`) intercepts all application-data (PSH) writes. Instead of the old `write_half.write_all(pending)` that dumped the full plaintext backlog through `SnowyStream::poll_write`'s passive chunking, a new `drive_shaper` loop operates:

1. **Policy query**: `shaper.next_data_policy(pending_len)` returns a `ShapePolicy { target_wire_len, delay, fake, allow_full_block }`.
2. **Slice / truncate**: if `pending` exceeds the payload capacity implied by `target_wire_len`, only that many bytes are taken; the remainder stays in `pending` for subsequent iterations. E.g. 5000 bytes of backlog against an 800-byte target → one 800-byte record emitted, 4200 bytes retained.
3. **Precise pad**: if `pending` is smaller than the target capacity, the record is emitted at the exact `target_wire_len` with noise-pool padding.
4. **Encrypt**: `SnowyStream::prepare_data_record(slice, target_wire_len, PadFill::Entropy)` encrypts exactly one record whose on-wire size equals `target_wire_len`.
5. **Flush** + **delay** + **advance**: the record is flushed, `tokio::time::sleep(delay)` injected if non-zero, then the shaper's packet sequence number and Markov state advance.
6. **Fake response**: if the policy carries `fake`, a `CMD_PADDING` request frame is queued on the control path before the next slice.

This erases the passive trace: the same application write produces different record boundaries depending solely on the shaper's policy, not on the inner payload structure.

### 3.4 Markov Macro-State Machine

The shaper maintains three macro-states that govern sizing policy over the connection's full lifecycle (no hard "first-N-packet" cliff):

| State | Sizing | Delay | Description |
|---|---|---|---|
| `HandshakeShaping` | Min-size (exact payload fit) | None | Active during the Noise handshake phase; tight coupling to avoid interference with auth framing. |
| `InteractiveControl` | Sampled from HTTP/2 discrete + HEADERS distributions (reuses `control_size`) | 15% chance Log-Normal IAT | Mimics web-application request/response patterns with variable-sized records. |
| `AsymmetricBulk` | Full MTU-anchored records (`max_data_record_wire_len` ≈ 16406) | None | Sustained high-throughput transfers; removes fragmentation caps to anchor sizes to realistic web-framing boundaries. |

**Transition logic**: state is re-evaluated per emitted packet using a sliding window of recent payload sizes (`RECENT_WINDOW_SIZE = 8`):
- `InteractiveControl → AsymmetricBulk`: at least `BULK_ENTRY_THRESHOLD` (3) of the last 8 payloads are full-capacity — indicating a sustained large transfer.
- `AsymmetricBulk → InteractiveControl`: at least `BULK_EXIT_THRESHOLD` (6) of the last 8 payloads are small — transfer is winding down.
- `HandshakeShaping →`: After ≥6 control frames (handshake complete), the shaper enters `InteractiveControl` (if scripted prefix still active, script rules govern instead).

### 3.5 Restls-Style Script Engine

The script engine provides deterministic control over the first 12 post-handshake data packets (`SCRIPTED_PACKET_PREFIX`). Each rule defines:

```
ScriptRule { len_lo, len_hi, delay: DelaySpec, expect_responses: u8 }
```

- `len_lo..=len_hi`: the record's **application-content size** (used to compute `target_wire_len`), sampled uniformly — **decoupled from the real pending payload size**.
- `delay` (`DelaySpec::None` or `DelaySpec::LogNormal{mu,sigma}`): inter-record delay sampled from a fitted log-normal distribution.
- `expect_responses`: if >0, a `CMD_PADDING` request frame is emitted after this data record, demanding M split replies from the peer.

Scripts are sourced from an embedded default (6 rules), overridable via the `traffic_script` config field (§8). The script parser supports comments (`#`) and blank lines. Config validation parse-checks each line at startup and emits a non-fatal warning on malformed rules (the embedded default is used as fallback).

Format example:
```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 300~400, Delay: 1.5~0.5, FakeResponse: 2
```

### 3.6 IAT Delay Modeling

Inter-record delays use a **log-normal distribution** sourced via Box-Muller normal sampling (`sample_log_normal(mu, sigma)` → `Duration::from_micros`). This fits the right-skewed, positive-definite distribution of real TCP inter-arrival times better than uniform or exponential jitter. The Markov InteractiveControl state applies a 15% delay probability; the script engine applies delays per-rule. AsymmetricBulk state uses zero delay (back-to-back emission) to preserve throughput.

### 3.7 Noise Pool (Entropy Alignment)

All padding bytes in shaped data records and `CMD_PADDING` junk payloads are sourced from a single **8 MiB CSPRNG-seeded entropy pool** (`crates/tunnel/src/entropy.rs`, `ENTROPY_POOL`). The pool is:
- Pre-generated from `rand::thread_rng()` (a CSPRNG) on startup (both client and server).
- Read **circularly** via a global atomic cursor — no state beyond position; no distribution shaping or entropy modeling.
- **Cryptographically isomorphic** to genuine AEAD ciphertext (~8 bits/byte unstructured entropy), so padded regions are statistically indistinguishable from real encrypted records in the observer's view.

`encrypt_variable_block(pad_fill: PadFill)` selects the fill source: `PadFill::Zero` for the control path, `PadFill::Entropy` for the shaped data path. This replaces the legacy zero-fill and `rand::thread_rng()` inline padding.

### 3.8 Fake Response Engine (CMD_PADDING)

`CMD_PADDING` (opcode 0x08) is a session-level control frame that carries:

```
| flag(1B) | m(1B) | junk(noise-pool) |
  flag = 0 → request    1 → reply
```

- **Request** (`flag=0`): emitted by the sender on the **Control** queue (priority) when a script rule or policy specifies `expect_responses = M`. Junk bytes from the noise pool.
- **Reply** (`flag=1`): the receiver, upon decoding a request, immediately emits `M` **independently split** reply frames (each a separate noise-pool-filled control record of varied size) back to the sender. This deliberately breaks the one-request/one-response symmetry of the application data layer.
- Reply frames are never delivered to streams — discarded silently at the frame handler level (count as read activity for idle-timeout purposes).
- The noise pool fills both request and reply junk, keeping all padding bytes isomorphic to ciphertext.

### 3.9 Wire Record Size Reference

Every post-handshake record is a 0x17 record with a 5-byte header (`| 0x17 | 0x03 | 0x03 | len(u16 BE) |`) followed by Noise-encrypted ciphertext. Each plaintext carries: `[length_prefix(2B, BE) | payload | padding(noise-pool) | inner_content_type(1B, 0x17)]`.

| Record Type | Wire Size (= 5 + cipher) | Sizing Control | Padding Source |
|---|---|---|---|
| Shaped data record | **shaper-dictated** (24–16406) | `TrafficShaper::next_data_policy` → `prepare_data_record(target_wire_len, Entropy)` | Noise pool |
| Control frame | discrete (33–82) or headed (124–824) → §3.2 | `control_size::next_control_size` → `prepare_control_record(payload, size)` | Zero |
| Flight3 CCS | **6** (unencrypted) | Hardcoded | — |
| Flight3 Finished ghost | **58** | 37 + 16 AEAD + 5 header | — |
| Flight3 H2 ghost | **86 / 92 / 98** | context-hash selects variant | — |
| Close notify alert | **24** (3 + 16 + 5) | Hardcoded `[01 00 15]` | — |
| Ghost record (server) | **5 + cache_size** | camouflage cache | Noise pool (legacy ENTROPY_POOL) |

---

## 4. Session Multiplexing

### 4.1 Frame Protocol

7-byte header per frame:

```
| cmd (1) | stream_id (4, BE) | data_len (2, BE) | payload (0–65535) |
```

| Command | Opcode | Purpose |
|---|---|---|
| SYN | 0x01 | Open stream |
| PSH | 0x02 | Push data |
| FIN | 0x03 | Close stream (half-close) |
| SETTINGS | 0x04 | Session capability negotiation |
| SYNACK | 0x07 | Stream open acknowledgment |
| PADDING | 0x08 | Fake-response engine (§3.8); request/reply noise-pool frames |

### 4.2 Pipelined Stream Open

Client stream open fuses `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` into one control-class coalesced write flush. The first stream on a fresh session defers its SYN via `DeferredUnsent` state — the SETTINGS frame (held in `PendingClientSettings`) and the SYN frame are buffered in the `Stream` object without being sent. On the first `write()` call, `write_gather_open()` takes the SETTINGS frame via `PendingClientSettingsGuard`, prepends it before the SYN, then appends target and data PSH frames. All are packed into a single `submit_write_packets` call with `FlushBehavior::Immediate`, producing one coalesced write flush.

The server validates the target, resolves DNS, and establishes the relay connection before issuing SYNACK. SYNACK thus confirms actual reachability — not just stream acceptance.

### 4.3 Idle Teardown

The session read loop (`run_read_loop`) uses a pinned `tokio::time::sleep` timer (`idle_timeout_with_jitter_secs`, default 45 s from config). On each successful read, the timer is reset to `now + idle_duration`. If the timer fires while no active streams, pending inbound streams, or pending open streams exist (`is_idle_timeout_eligible()`), the session tears down gracefully: a Noise-encrypted TLS `close_notify` alert (0x15) is sent, followed by TCP FIN. No application-layer heartbeat (CMD_PING) is sent — kernel TCP keepalive (60 s idle, 30 s interval, 3 retries) serves as the dead-peer detection mechanism instead.

---

## 5. Anti-Active-Probing

### 5.1 Decryption Failure

When a received 0x17 record fails Noise AEAD decryption (`read_message` returns `Err`), the tunnel does NOT send any alert. Instead:

1. `close_notify_written` is immediately set to `true`, preventing the normal `close_notify` from ever being sent.
2. An `InvalidData` IO error is returned.
3. The session read loop receives the error and tears down the TCP connection.
4. No bytes are written back to the peer — the connection is silently closed.

The peer observes either TCP FIN or RST (OS-dependent), with no TLS-layer alert payload, preventing active probing that relies on distinguishing alert types.

### 5.2 Pre-Auth Fallback

Failures before Noise authentication is committed (non-TLS first record, auth failure, SNI mismatch, handshake timeout) can optionally relay the client traffic transparently to the camouflage endpoint. This is bounded:

| Limit | Value |
|---|---|
| Global concurrent fallbacks | 384–768 (randomized at startup) |
| Per-IP concurrent fallbacks | 12–24 (randomized) |
| Fallback connect timeout | 2–5 s (randomized) |
| IP cooldown threshold | 75–150 fallbacks per 3000–4200 s window → 240–420 s cooldown |

---

## 6. Fingerprint-Specific Presets

The `fingerprint` config field selects the ClientHello generation strategy:

| Preset | Source | Cipher Suite Order | Key Share Groups |
|---|---|---|---|
| `firefox` | Captured bootstrap hex blob | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519, SECP256R1 |
| `rustls` | Native rustls TLS 1.3 | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | X25519, SECP256R1, SECP384R1 |
| `python-openssl` / `baseline` | Captured bootstrap hex blob | AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM | X25519, SECP256R1 |

Firefox and Python-OpenSSL presets preserve the captured record shape (extension order, padding, record length) exactly. The rustls preset uses live rustls generation with GREASE rotation.

A custom ClientHello hex file can override the Firefox/Python-OpenSSL templates via `template_path`. The rustls preset ignores `template_path`.

---

## 7. Error Handling State Machine

```
                                 ClientHello arrives
                                        │
                        ┌───────────────┴─────────────────────┐
                        │ First record is 0x16?               │
                        └─────────────┬────────┬──────────────┘
                                 Yes  │        │ No
                                      │        ▼
                                      │  Pre-Auth Fallback
                                      │  → transparent relay
                                      │
                                      ▼
                          Noise auth + counter replay + MAC
                          (single atomic check)
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ All pass?                          │
                        └─────────────┬────────┬─────────────┘
                                  Yes │        │ No
                                      │        ▼
                                      │  Pre-Auth Fallback
                                      │  (covers Noise, counter
                                      │   MAC, and replay)
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ SNI matches camouflage?            │
                        └─────────────┬────────┬─────────────┘
                                  Yes │        │ No
                                      │        ▼
                                      │  Pre-Auth Fallback
                                      │
                                      ▼
                             Commit counter replay
                                      │
                                      ▼
                           Synthetic camouflage replay
                                      │
                                      ▼
                           Noise transport established
                                      │
                        ┌─────────────┴───────────────────────┐
                        │ Decrypt error on 0x17?              │
                        └─────────────┬───────────────────────┘
                                 Yes  │
                                      ▼
                         Silent close — no alert sent.
                         TCP FIN or RST (OS-dependent).
```

---

## 8. Session Configuration

The `session` block (optional, under `settings` in both client outbounds and server inbounds) controls per-session behavior:

| Field | Type | Default | Description |
|---|---|---|---|
| `max_streams_per_session` | usize | 256 | Maximum concurrent multiplexed streams per tunnel session. |
| `idle_timeout_secs` | u64 | 45 | Session idle teardown timeout (with ±10% jitter). |
| `traffic_script` | optional string | (embedded default) | Restls-style script controlling the first 12 post-handshake data packets (§3.5). Example: `"Length: 200~250, Delay: 0, FakeResponse: 0\nLength: 300~400, Delay: 2.0~0.5, FakeResponse: 1"`. Malformed rules trigger a non-fatal startup warning; the embedded default is used as fallback. |

The embedded default script:
```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 180~220, Delay: 1.5~0.6, FakeResponse: 0
Length: 250~350, Delay: 0, FakeResponse: 1
Length: 300~400, Delay: 2.0~0.5, FakeResponse: 0
Length: 200~300, Delay: 0, FakeResponse: 1
Length: 400~600, Delay: 3.0~0.7, FakeResponse: 0
```

After the scripted prefix is exhausted, the TrafficShaper's Markov state machine (§3.4) governs sizing and delay for the remainder of the connection lifecycle. No configuration surface exists for the Markov transition parameters — they are derived from the sliding window of recent payload sizes and are directionally symmetric.
