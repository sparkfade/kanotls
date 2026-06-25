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

## 3. Data-Stream Bimodal Distribution

### 3.1 Bulk Class

Large data writes (> 16382 bytes of application payload) are split into full TLS records:

- **Plaintext**: `[length_prefix(2B, BE) | data(16382B) | inner_content_type(1B, 0x17)]` = 16385 bytes
- **Ciphertext** (ChaChaPoly): 16385 + 16 = 16401 bytes
- **Wire record**: 5 (header) + 16401 = **16406 bytes**

When `poll_flush()` drains remaining data (0 < n ≤ 16382 bytes), `encrypt_padded_block()` applies **jittered padding**: with 80% probability, exponential-distribution padding (λ = 0.050295, CDF(32) ≈ 0.80) capped at 32 bytes is used; with 20% probability, the block is padded to the full 16385-byte plaintext. This produces a natural spread of tail record wire sizes (n + 24 to 16406) that avoids the identifiable exact-truncation or fixed-full-block signatures.

### 3.2 Control Class

Micro-frames (CMD_SYN, CMD_FIN) use `encrypt_variable_block()`. Control record wire sizes are determined by a **state-aware sampler** in `control_size`:

- **Handshake state** (first 6 control frames): 7 discrete sizes (33, 37, 46, 51, 64, 69, 82) mimicking HTTP/2 SETTINGS, SETTINGS_ACK, WINDOW_UPDATE, and merged variants. 5% of frames additionally sample from a truncated-normal HEADERS frame distribution (C2S: μ=450, σ=120, [250, 800]; S2C: μ=200, σ=50, [100, 400]).
- **Transport state** (6+ control frames): 5 discrete sizes (33, 37, 41, 46, 54) mimicking PING, WINDOW_UPDATE, SETTINGS_ACK, and merged variants (no SETTINGS sizes). 10% of frames sample from the same HEADERS frame distribution.

`FlowDirection` (C2S vs S2C) selects the parameters for the HEADERS-frame truncated-normal sampler, producing directionally distinct distributions.

Control records take priority: any accumulated bulk data in `tx_agg_buf` is flushed first (as exact-size padded blocks), then the control record is emitted.

### 3.3 Entropy Sources

| Padding location | Source |
|---|---|
| Ghost record payloads (server) | `ENTROPY_POOL` — 8 MiB pre-seeded `thread_rng` bytes, circular read |
| Ghost record structure header | Hardcoded 16-byte fake ticket header `[0x22, 0x00, ...]` |
| `encrypt_variable_block()` tail | Zero bytes, with last byte = `0x17` (inner content type) |
| `encrypt_full_block()` tail | Last byte = `0x17` (inner content type), no other unused space |

### 3.4 Post-Handshake Wire Record Size Reference

Every record on the wire after the TLS handshake is a 0x17 (Application Data) record with a 5-byte header (`| 0x17 | 0x03 | 0x03 | len(u16 BE) |`) followed by Noise-encrypted ciphertext. Internally, each plaintext carries a 2-byte length prefix, the payload bytes, optional zero padding, and a 1-byte inner content type (`0x17` for app data, `0x15` for alert) — matching the TLS 1.3 `TLSInnerPlaintext` structure.

| Record Type | Plaintext Formula | Ciphertext (= plain + 16) | Wire Size (= 5 + cipher) | Example (n bytes data) |
|---|---|---|---|---|
| Full bulk block | `2 + 16382 + 1 = 16385` | 16401 | **16406** | n = 16382 → 16406 |
| Tail bulk (jittered) | `2 + n + 1` + padding to 16385 | plain + 16 | **n + 24** to **16406** | n = 866 → ~890–16406 |
| Control frame | `2 + payload` + zero-pad + 1B ICT to target | target + 16 | discrete 33-82 or 124-824 (see §3.2) | CMD_SYN (7B): 69 |
| Flight3 CCS | — | — | **6** (unencrypted) | — |
| Flight3 Finished ghost | 37 | 53 | **58** | — |
| Flight3 H2 ghost | 65 / 71 / 77 | 81 / 87 / 93 | **86 / 92 / 98** | context-hash selects variant |
| Close notify alert | 3 (`[01 00 15]`) | 19 | **24** | — |
| bad_record_mac alert | 2 (`[02 14]`) | 18 | **23** | — |
| Ghost record (server) | size from camouflage cache | size + 16 | **5 + cache_size** | first 16B = fake ticket header |

Tail bulk records use jittered padding — 80% carry at most 32 bytes of padding (exponential distribution), while 20% are padded to the full block size of 16406 bytes.

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

### 4.2 Pipelined Stream Open

Client stream open fuses `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` into one control-class coalesced write flush. The first stream on a fresh session defers its SYN via `DeferredUnsent` state — the SETTINGS frame (held in `PendingClientSettings`) and the SYN frame are buffered in the `Stream` object without being sent. On the first `write()` call, `write_gather_open()` takes the SETTINGS frame via `PendingClientSettingsGuard`, prepends it before the SYN, then appends target and data PSH frames. All are packed into a single `submit_write_packets` call with `FlushBehavior::Immediate`, producing one coalesced write flush.

The server validates the target, resolves DNS, and establishes the relay connection before issuing SYNACK. SYNACK thus confirms actual reachability — not just stream acceptance.

### 4.3 Idle Teardown

The session read loop (`run_read_loop`) uses a pinned `tokio::time::sleep` timer (`idle_timeout_with_jitter_secs`, default 45 s from config). On each successful read, the timer is reset to `now + idle_duration`. If the timer fires while no active streams, pending inbound streams, or pending open streams exist (`is_idle_timeout_eligible()`), the session tears down gracefully: a Noise-encrypted TLS `close_notify` alert (0x15) is sent, followed by TCP FIN. No application-layer heartbeat (CMD_PING) is sent — kernel TCP keepalive (60 s idle, 30 s interval, 3 retries) serves as the dead-peer detection mechanism instead.

---

## 5. Anti-Active-Probing

### 5.1 Decryption Failure

When a received 0x17 record fails Noise AEAD decryption (`read_message` returns `Err`), the tunnel does NOT send a normal `close_notify`. Instead:

1. A TLS 1.3 fatal alert `bad_record_mac` (0x02, 0x14) is constructed and Noise-encrypted.
2. The alert is wrapped as a 0x17 record and queued in the write buffer.
3. `SO_LINGER` is set to 0 on the TCP socket (forces RST on close).
4. `close_notify_written` is set to `true` and state to `Closed` (prevents the normal `close_notify` from ever being sent).
5. An IO error is returned, triggering session teardown and TCP RST.

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
                        bad_record_mac fatal alert
                        + SO_LINGER=0 + TCP RST
```
