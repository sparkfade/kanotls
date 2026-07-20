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

**Transition logic**: state is re-evaluated per emitted packet using **probabilistic smoothing**. The probability `p_bulk = pending_len / max_pending_flush_size` drives transitions: a nearly-full pending backlog strongly biases entry into `AsymmetricBulk`, while a drained buffer biases exit back to `InteractiveControl` (exit probability capped at 85%). This replaces the v1.1 deterministic thresholds with a continuous probability ramp that avoids state oscillation at the boundary.

### 3.5 Declarative Traffic Script Engine

The traffic script engine provides deterministic, replayable control over the sequence of post-handshake data record sizes, inter-record delays, and peer-interaction signals. It is driven by a user-supplied (or embedded default) list of rules, one per emitted packet, cycled via `packet_seq % script.len()`. This allows the operator to pre-program a specific packet-size trace that mimics a known target application (e.g. a TLS-encrypted video stream or web-browsing session) without coupling the record size to the actual tunneled payload.

**Rule structure:**
```
ScriptRule { len_lo, len_hi, delay: DelaySpec, expect_responses: u8 }
```

| Field | Meaning |
|---|---|
| `len_lo`..`len_hi` | The **application‑content byte count** to embed in this record. Sampled uniformly from the interval. The shaper computes `target_wire_len = MIN_DATA_WIRE_LEN + (len_lo..len_hi)`, pads to that exact wire size, and encrypts. Any real pending data up to `len_lo..len_hi` bytes is consumed; if the pending backlog is smaller, noise-pool padding fills the gap. If the backlog is larger, only a chunk is taken — the remainder stays in `pending` for the next iteration. |
| `delay` | `DelaySpec::None` (zero delay) or `DelaySpec::LogNormal{mu_ms, sigma_ms}` (inter-record pause sampled from a fitted log‑normal distribution). See §3.6. |
| `expect_responses` | If `> 0`, the sender queues a `CMD_PADDING` request (opcode 0x08) on the **Control** channel *immediately after* this data record is flushed. The peer, upon decoding the request, responds with `M` independently-split reply frames (§3.8). The field is set to `0` for normal unilateral-data rules. |

**Script lifecycle and blend window:**

The script runs for `script.len()` packets. After the last rule is consumed, the engine enters a **smooth blend window** of `SCRIPT_BLEND_WINDOW = 6` packets. Within this window the probability of falling through to the Markov state machine (§3.4) ramps linearly from 0% to 100%. This eliminates the abrupt "first‑N‑packets‑then‑Markov" cliff, producing a gradual handover that is not fingerprintable via inter‑record size discontinuities.

After the blend window, the TrafficShaper's Markov machine takes over for the remainder of the connection lifetime. No configuration surface exists for the Markov parameters — they are derived solely from the pending-backlog pressure via the probabilistic `p_bulk` ramp (§3.4).

**Post-script shaping switch (`post_script_shaping`):** the optional `session.post_script_shaping` config field selects what happens once the script is exhausted. The default `"markov"` behaves as described above (blend window → Markov machine). `"off"` disables all post-script shaping: once `packet_seq` reaches `script.len()`, every subsequent record carries exactly the pending payload (wire size = pending + fixed record overhead), with zero delay, no fake frames, and no blend window — plaintext size maps directly to wire size from that point on. The bulk fast path and bulk hysteresis (§3.4) still take priority in both modes. Any value other than `"markov"`/`"off"` triggers a non-fatal startup warning and is treated as unset.

**Packet flow example — client → server, 3‑rule script:**

Assume the following `traffic_script`:
```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 300~400, Delay: 2.0~0.5, FakeResponse: 1
Length: 180~220, Delay: 1.5~0.6, FakeResponse: 0
```

Real application data queued: 6000 bytes.

| Packet # | Rule | Sampled `len` | Actual data consumed | Wire record size | Post‑record action |
|---|---|---|---|---|---|
| 1 | Rule 0 | 215 | 215 bytes (from backlog) | `MIN_DATA_WIRE_LEN + 215` (≈ 239) | Flush. No delay. `packet_seq` → 1. Backlog remaining: 5785. |
| 2 | Rule 1 | 362 | 362 bytes | `MIN_DATA_WIRE_LEN + 362` (≈ 386) | Flush. `sleep(log_normal(2.0, 0.5))`. Then: queue `CMD_PADDING(flag=0, m=1)` on Control channel. Backlog remaining: 5423. |
| 3 | Rule 2 | 197 | 197 bytes | `MIN_DATA_WIRE_LEN + 197` (≈ 221) | Flush. `sleep(log_normal(1.5, 0.6))`. Backlog remaining: 5226. |

After packet 3 the script has exhausted its 3 rules. Packets 4–9 are emitted within the **6‑packet blend window**: each has an increasing probability (≈17%, 33%, 50%, 67%, 83%, 100%) of being governed by the Markov machine instead of re‑cycling the script. Packet 10+ are entirely Markov‑controlled.

**What the server sees on the wire (packet 2 sequence):**

1. Server receives a 0x17 record of wire size ≈ 386 bytes → Noise‑decrypt → plaintext `[len_prefix(2B) | 362B payload | padding | 0x17]` → 362 bytes delivered to the stream.
2. After a log‑normally sampled pause (e.g. 1.8 ms), server receives a **Control‑class 0x17 record** containing a `CMD_PADDING` request (`cmd=0x08, flag=0, m=1`).
3. Server's frame handler immediately emits 1 `CMD_PADDING` reply frame (`cmd=0x08, flag=1`, junk from noise pool) back to the client on the Control channel. This reply frame is a separate 0x17 record with a size sampled from the Control class transport pool (33–82 or 124–824 bytes, §3.2).
4. The reply frame is never delivered to any stream — it is decoded and discarded at the session frame‑handler level, acting purely as cover traffic to break one‑request/one‑response symmetry.

Scripts are sourced from an embedded default (6 rules, listed in §8), overridable via the `traffic_script` config field. The script parser supports `#` comments and blank lines. Config validation parse‑checks each line at startup; malformed lines trigger a non‑fatal warning and the embedded default is used as fallback.

Besides `lo~hi`, the `Length` field also accepts `base?range`: the value is sampled once per connection at shaper construction as `base + U[0, range]` and then stays fixed for that connection's lifetime. After parsing, every connection randomizes its script in `TrafficShaper::new`: the rule order is rotated by a random offset and each rule's length window is scaled by an independent sample from U[0.85, 1.20] (clamped to ≥ 1 and ≤ data-record capacity), so the position→size mapping is not constant across connections.

Format example:
```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 300~400, Delay: 1.5~0.5, FakeResponse: 2
```

### 3.6 IAT Delay Modeling

Inter-record delays use a single non-zero delay specification (`DelaySpec::None` means zero delay):

- **`DelaySpec::LogNormal { mu_ms, sigma_ms }`**: Log-normal distribution sourced via Box-Muller normal sampling (`sample_log_normal(mu, sigma)` → `Duration::from_micros`). This fits the right-skewed, positive-definite distribution of real TCP inter-arrival times better than uniform or exponential jitter.

The Markov `InteractiveControl` state applies a 15% delay probability; the script engine applies delays per-rule. `AsymmetricBulk` state uses zero delay (back-to-back emission) to preserve throughput.

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

> **Server-side only**: client sessions are lifecycle-managed by the connection pool (idle drain / soft TTL). The idle-teardown branch in `run_read_loop` is gated off client-side via `idle_teardown_enabled = !is_client`.

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
| Global concurrent fallbacks | 512 (fixed) |
| Per-IP concurrent fallbacks | 16 (fixed) |
| Fallback connect timeout | 3 s (fixed) |
| IP cooldown threshold | 112 fallbacks per 3600 s window → 300 s cooldown |

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
| `traffic_script` | optional string | (embedded default) | Declarative script controlling post-handshake data packets (§3.5). Rules are cycled with `packet_seq % N` and transition to the Markov machine via a 6-packet smooth blend window. Example: `"Length: 200~250, Delay: 0, FakeResponse: 0\nLength: 300~400, Delay: 2.0~0.5, FakeResponse: 1"`. Malformed rules trigger a non-fatal startup warning; the embedded default is used as fallback. |
| `post_script_shaping` | optional string | `"markov"` | Post-script shaping mode (§3.5). `"markov"` (default): blend window → Markov machine. `"off"`: once the script is exhausted, records are emitted at their exact pending size with zero delay and no fake frames. Invalid values trigger a non-fatal startup warning and are treated as unset. |

The embedded default script:
```
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 180~220, Delay: 1.5~0.6, FakeResponse: 0
Length: 250~350, Delay: 0, FakeResponse: 1
Length: 300~400, Delay: 2.0~0.5, FakeResponse: 0
Length: 200~300, Delay: 0, FakeResponse: 1
Length: 400~600, Delay: 3.0~0.7, FakeResponse: 0
```

After the script rules are exhausted (with the smooth blend window bridging into the Markov machine), the TrafficShaper's Markov state machine (§3.4) governs sizing and delay for the remainder of the connection lifecycle. No configuration surface exists for the Markov transition parameters — they are derived from the pending backlog pressure via a probabilistic `p_bulk` ramp and are directionally symmetric.
