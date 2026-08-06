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

**Multi-user authentication.** The server inbound is configured with a `users` list (`{name, password}`), and each password is expanded at startup into an independent `derived_psk` via `derive_psk()`. During the handshake the server probes every candidate PSK against the ClientHello in the order **counter-MAC → ephemeral-key unmasking → `read_message()` → counter replay → ephemeral replay**, and the first PSK that passes all checks identifies the authenticated user (`authenticate_client_hello()` in `crates/tunnel/src/server/mod.rs`).

**The counter MAC must come first.** Its four inputs (`derived_psk`, the ClientHello `random`, the masked counter, and the first 16 bytes of `random`) all come from raw ClientHello bytes and are independent of any Noise state, so it can be hoisted unconditionally. Measured, `build_responder()` + `read_message()` costs ~6.3–8.0 µs while the counter MAC costs ~0.2–0.3 µs — a **27–32× difference**. With the MAC first, a non-matching candidate costs one keyed hash and no AEAD, so 512 concurrent handshakes × 50 users drops from ~161–206 CPU-ms to ~5–8 CPU-ms. This is both a multi-user speedup and the closure of an amplification vector: previously a garbage ClientHello forced a full probe against **every** configured user.

> **Attribution correction**: `Noise_NNpsk0`'s first message pattern is `-> psk, e`, so the responder's `read_message` performs only `mix_key_and_hash(psk)`, `mix_hash(e)`, `mix_key(e)` and one 16-byte AEAD decryption — **all symmetric, with no X25519 scalar multiplication**. The elliptic-curve work happens in `write_message` (the response side, once per accepted handshake). The earlier claim that a probe costs "a few hashes plus one AEAD decryption" understated it: it is three HKDF-BLAKE2s chains. The identified user name is attached to the connection and is available to the routing engine via the `auth_user` rule field.

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
| `first_app_data_delay_us` | **Microseconds** between ServerHello arrival and the first 0x17 record |
| `early_app_data_gap_us` | Inter-record gaps between consecutive 0x17 records (**microseconds**) |
| `has_ccs` | Whether the reference endpoint sent a CCS record |

### 2.2 Startup Health Check

On server boot, `validate_camouflage_endpoint()` sends a fresh template-instantiated ClientHello (same Firefox template the clients use) to the reference endpoint 4 times. Each flight is fingerprinted (random/session_id/key_share zeroed, padding extension normalized) and cached under both a per-fingerprint key and a fingerprint-family baseline key (first 8 hex chars of the fingerprint hash).

### 2.3 Per-Connection Replay

When a client connects:

1. ClientHello is fingerprinted via `stable_client_hello_fingerprint()`.
2. The server looks up the best cached profile (prefers complete profiles: rank 3 = has both server_records and app_data_sizes).
3. If no complete profile is cached, `fetch_camouflage_flight()` performs a live fetch to the reference endpoint (with refresh-gate deduplication).
4. `establish_synthetic_camouflage_tunnel()`:
   - Echoes the client's `session_id` into the cached ServerHello. A length mismatch means the cached profile is inconsistent with this connection, so the handshake is rejected rather than replaying an echo the client never sent (RFC 8446 §4.1.3).
   - Replaces the ServerHello `random` with fresh bytes (preserving downgrade-sentinel if present).
   - **Regenerates the ServerHello `key_share`** — the server's ephemeral ECDHE public key — per connection, group-aware: X25519 and secp256r1 get genuine ring-generated keypairs (random bytes would not be a valid curve point, and a random 32-byte "X25519 key" sets the high bit half the time whereas a real u-coordinate never does); the ML-KEM-768 half of X25519MLKEM768 is densely packed, so uniform random bytes are both valid and correctly distributed. Without this the cached profile is replayed verbatim and the server hands out the *same* ECDHE public key on every connection — at most 4 distinct values rotating on the 300–3000 s refresh cycle. A repeated server share is cryptographically impossible for a genuine endpoint, so storing 32 bytes per flow identifies the server from two connections with no false positives. An unsupported group fails the handshake closed rather than emitting the fingerprint.
   - Emits all visible handshake records.
   - Emits prefix 0x17 records (too small to carry Noise), filled with fresh `rand::thread_rng()` bytes.
   - Emits the Noise response wrapped in a 0x17 record (sized to match the first cached app_data size, with the Noise server public key XOR-masked in the first 32 bytes).
   - Emits ghost 0x17 records (sized per cache), filled with fresh `rand::thread_rng()` bytes.

> **Every plaintext byte the server emits after ServerHello must be freshly random per connection.** These records impersonate NewSessionTicket, which in TLS 1.3 lives inside an encrypted record and is therefore uniformly random on the wire. Two earlier designs violated this and were removed:
>
> - A fixed 16-byte `22 00…00` "fake session-ticket structure header" was prefixed to every ghost record. Being constant, plaintext, and at a fixed offset, it was identifiable with a single 16-byte `memcmp` at a 2^-128 false-positive rate — and it repeated up to 255 times per connection.
> - Payloads were drawn circularly from a process-lifetime 8 MiB entropy pool, so different connections shared byte-identical multi-hundred-byte substrings. Real AEAD ciphertext never repeats; the reuse let an observer join flows to the same server process. Measured empirically: with ~1.8 KB of ghost payload per connection, a collision appears within ~64 connections.
>
> `crates/tunnel/src/server/wire_tests.rs` now asserts both properties (no constant byte position, no shared 16-byte window across connections) and fails CI on regression.

### 2.4 Background Refresh

A daemon per (host, port) pair refreshes the profile every 300–3000 seconds (randomized), using the same ClientHello fingerprint as the probe.

---

## 3. Active Traffic Shaping

### 3.1 Design Rationale

The original bimodal distribution (§3.1–3.4 in v1.0) passively split application payloads at `BLOCK_DATA_CAPACITY` (16382) boundaries and applied probabilistic tail padding. This mapped the inner-TLS plaintext size directly onto the wire record length, exposing structural signatures (e.g., a 5000-byte certificate would produce 16382 + 16382 + 1236 = three records whose sizes leak the inner handshake shape). v1.1 replaces this with a **top-down active TrafficShaper** that dictates every record's on-wire length independently of the application payload — plaintext length never maps to wire length.

### 3.2 Control Class

Protocol frames (CMD_SYN, CMD_FIN, CMD_SETTINGS, CMD_SYNACK, CMD_PADDING) use `encrypt_variable_block`. Their wire sizes are determined by a **state-aware sampler** in `control_size`:

- **Opening sequence** (`h2_opening_size`, `H2_OPENING_MAX_LEN = 3`): **deterministic**, not sampled.
  - **C2S, 1 record**: `SETTINGS-ACK` (33). The client's own `preface + SETTINGS + WINDOW_UPDATE` already went out as the Flight-3 H2 ghost record (the 86/92/98 row in §3.9), so the control-record stream begins *after* the H2 preamble; what remains of a real Firefox opening is exactly the ACK answering the server's SETTINGS.
  - **S2C, 3 records**: `SETTINGS` (51 or 69) → `WINDOW_UPDATE` (37) → `SETTINGS-ACK` (33), all three in one flush (121/139 bytes, one segment). This is the nginx/h2o server opening.
  - **No length randomization and no blend window**: a real H2 opening-to-steady-state transition *is* a hard switch (after SETTINGS-ACK, SETTINGS never recurs), so the hard boundary is fidelity, not a defect. The only variation is how many parameters SETTINGS carries (selecting the small/large size), fixed **per process** via `OnceLock` — a real endpoint's SETTINGS content is decided at compile time.

  The previous model sampled each of the first 6 control frames independently from a weighted pool containing SETTINGS, with 0.78 weight on SETTINGS-bearing sizes ⇒ ~4.7 SETTINGS-shaped frames per direction where real H2 sends one; and the switch point was the global constant 6, identical across every connection and deployment.

- **Transport state** (after the opening sequence is exhausted): 5 discrete sizes (33, 37, 41, 46, 54) mimicking PING, WINDOW_UPDATE, SETTINGS_ACK and merged variants (**no SETTINGS sizes**). 10% of frames sample from a truncated-normal HEADERS distribution (C2S: μ=450, σ=120, [250, 800]; S2C: μ=200, σ=50, [100, 400]).

- **Records carrying `CMD_SYN` / `CMD_FIN` are the exception**: they are sized from the same sampler as data records (`next_data_record_payload`), **not** from the control discrete pool. Measured rationale in §9.3: all five control-pool sizes fall in `L1` (≤160), and at close the local FIN and the peer FIN each occupy their own segment directly after the response body's last segment ⇒ **`(−L4, L1, −L1)` reproduced once every 4–5 closes**. In real H2 a stream opens with `HEADERS` and half-closes via `END_STREAM` on a `DATA` frame; neither is a tiny standalone frame.
  `CMD_SYNACK` is **deliberately excluded**: enlarging it pushes the server's opening flight past 1211 bytes, which then pairs with the client's legitimately 33-byte SETTINGS-ACK to form `(L2, −L4, L1)` (distinctiveness 7.226) — SYNACK's smallness is protective inside the birth window.

Each control record increments the TrafficShaper's internal control-frame counter (`note_control_frame()`), which governs the handshake-to-transport transition used by the shaper's Markov machine (§3.4).

### 3.3 TrafficShaper Architecture

The `TrafficShaper` (per-connection, owned by `SessionWriter::run`) intercepts all application-data (PSH) writes. Instead of the old `write_half.write_all(pending)` that dumped the full plaintext backlog through `SnowyStream::poll_write`'s passive chunking, a new `drive_shaper` loop operates:

1. **Policy query**: `shaper.next_data_policy(pending_len)` returns a `ShapePolicy { target_wire_len, delay, fake, allow_full_block }`.
2. **Slice / truncate**: if `pending` exceeds the payload capacity implied by `target_wire_len`, only that many bytes are taken; the remainder stays in `pending` for subsequent iterations. E.g. 5000 bytes of backlog against an 800-byte target → one 800-byte record emitted, 4200 bytes retained.
3. **Precise pad**: if `pending` is smaller than the target capacity, the record is emitted at the exact `target_wire_len` with zero padding.
4. **Encrypt**: `SnowyStream::prepare_data_record(slice, target_wire_len)` encrypts exactly one record whose on-wire size equals `target_wire_len`.
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

The traffic script engine provides deterministic, replayable control over the sequence of post-handshake data record sizes, inter-record delays, and peer-interaction signals. It is driven by a user-supplied (or embedded default) list of rules cycled via `packet_seq % rule_count` until `packet_seq` reaches the script's `stop` count (default: the rule count). This allows the operator to pre-program a specific packet-size trace that mimics a known target application (e.g. a TLS-encrypted video stream or web-browsing session) without coupling the record size to the actual tunneled payload.

**Rule structure:**
```
ScriptRule { len_lo, len_hi, delay: DelaySpec, expect_responses: u8, fake_jitter: i32 }
```

| Field | Meaning |
|---|---|
| `len_lo`..`len_hi` | The **application‑content byte count** to embed in this record. Sampled uniformly from the interval. The shaper computes `target_wire_len = MIN_DATA_WIRE_LEN + (len_lo..len_hi)`, pads to that exact wire size, and encrypts. Any real pending data up to `len_lo..len_hi` bytes is consumed; if the pending backlog is smaller, zero padding fills the gap. If the backlog is larger, only a chunk is taken — the remainder stays in `pending` for the next iteration. |
| `delay` | `DelaySpec::None` (zero delay) or `DelaySpec::LogNormal{mu_ms, sigma_ms}` (inter-record pause sampled from a fitted log‑normal distribution). See §3.6. |
| `expect_responses` | If `> 0`, the sender queues a `CMD_PADDING` request (opcode 0x08) on the **Control** channel. The peer, upon decoding the request, responds with `M` independently-split reply frames (§3.8). The field is set to `0` for normal unilateral-data rules. |
| `fake_jitter` | Position jitter for the fake response: each time the rule fires, an offset is sampled uniformly from `[min(0,k), max(0,k)]` records relative to the triggering record. A negative offset emits the request *before* the triggering record (the previous record's slot); zero pins it to the triggering record; a positive offset defers it, released when the target record is emitted (any remainder is flushed once the script reaches `stop`). This decorrelates the cover-frame cluster from its triggering record. |

**Script lifecycle and blend window:**

The script runs for `stop` packets (`stop` defaults to the rule count; a larger `stop` re-cycles the rules). After the last scripted packet, the engine enters a **smooth blend window** of `SCRIPT_BLEND_WINDOW = 6` packets. Within this window the probability of falling through to the Markov state machine (§3.4) ramps linearly from 0% to 100%. This eliminates the abrupt "first‑N‑packets‑then‑Markov" cliff, producing a gradual handover that is not fingerprintable via inter‑record size discontinuities.

After the blend window, the TrafficShaper's Markov machine takes over for the remainder of the connection lifetime. No configuration surface exists for the Markov parameters — they are derived solely from the pending-backlog pressure via the probabilistic `p_bulk` ramp (§3.4).

**Post-script shaping switch (`post_script_shaping`):** the optional `session.post_script_shaping` config field selects what happens once the script is exhausted. The default `"markov"` behaves as described above (blend window → Markov machine). `"off"` disables all post-script shaping: once `packet_seq` reaches `stop`, every subsequent record carries exactly the pending payload (wire size = pending + fixed record overhead), with zero delay, no fake frames, and no blend window — plaintext size maps directly to wire size from that point on. The bulk fast path and bulk hysteresis (§3.4) still take priority in both modes. Any value other than `"markov"`/`"off"` triggers a non-fatal startup warning and is treated as unset.

**Packet flow example — client → server, 3‑rule script:**

Assume the following `traffic_script`:
```json
"traffic_script": [
  "0=L:200-250,D:0,F:0",
  "1=L:300-400,D:2.0-0.5,F:0",
  "2=L:180-220,D:1.5-0.6,F:0"
]
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
3. Server's frame handler immediately emits 1 `CMD_PADDING` reply frame (`cmd=0x08, flag=1`, zero-filled junk) back to the client on the Control channel. This reply frame is a separate 0x17 record with a size sampled from the Control class transport pool (33–82 or 124–824 bytes, §3.2).
4. The reply frame is never delivered to any stream — it is decoded and discarded at the session frame‑handler level, acting purely as cover traffic to break one‑request/one‑response symmetry.

Scripts are sourced from an embedded default (6 rules, listed in §8), overridable via the `traffic_script` config field. The config value is a JSON string array: an optional `stop=N` control entry followed by indexed rules `i=L:...,D:...,F:...` whose index must match the rule's 0-based position. Config validation parses the array at startup; any malformed entry triggers a non‑fatal warning and the embedded default is used as fallback.

Besides `lo-hi`, the `L` field also accepts `base?range`: the value is sampled once per connection at shaper construction as `base + U[0, range]` and then stays fixed for that connection's lifetime. After parsing, every connection randomizes its script in `TrafficShaper::new`: the rule order is rotated by a random offset and each rule's length window is scaled by an independent sample from U[0.85, 1.20] (clamped to ≥ 1 and ≤ data-record capacity), so the position→size mapping is not constant across connections.

Format example:
```json
"traffic_script": [
  "stop=4",
  "0=L:200-250,D:0,F:0",
  "1=L:300-400,D:1.5-0.5,F:2?-1"
]
```

### 3.6 IAT Delay Modeling

Inter-record delays use a single non-zero delay specification (`DelaySpec::None` means zero delay):

- **`DelaySpec::LogNormal { mu_ms, sigma_ms }`**: Log-normal distribution sourced via Box-Muller normal sampling (`sample_log_normal(mu, sigma)` → `Duration::from_micros`). This fits the right-skewed, positive-definite distribution of real TCP inter-arrival times better than uniform or exponential jitter.

The Markov `InteractiveControl` state applies a 15% delay probability; the script engine applies delays per-rule. `AsymmetricBulk` state uses zero delay (back-to-back emission) to preserve throughput.

### 3.7 Record Padding

Padding bytes in shaped data records and `CMD_PADDING` junk payloads are **zero**, as specified by RFC 8446 §5.4 for TLS 1.3 record padding.

An earlier design sourced these bytes from an 8 MiB CSPRNG entropy pool on the theory that padding had to be "cryptographically isomorphic to genuine AEAD ciphertext." That rationale does not hold: every one of these bytes sits on the *plaintext* side of `encrypt_variable_block` and is subsequently encrypted with ChaCha20-Poly1305, so the observer sees ciphertext that is uniformly random regardless of what plaintext went in. The pool bought nothing here while costing a cache-hostile copy across 8 MiB plus a globally contended atomic cursor per record. It has been removed.

Randomness *is* required for the bytes the server writes in plaintext during the synthetic camouflage replay (§2.3); those are drawn per connection from `rand::thread_rng()`.

### 3.8 Fake Response Engine (CMD_PADDING)

`CMD_PADDING` (opcode 0x08) is a session-level control frame that carries:

```
| flag(1B) | m(1B) | junk(noise-pool) |
  flag = 0 → request    1 → reply
```

- **Request** (`flag=0`): emitted by the sender on the **Control** queue (priority) when a script rule or policy specifies `expect_responses = M`. Junk bytes are zero (encrypted alongside the frame).
- **Reply** (`flag=1`): the receiver, upon decoding a request, emits `M` **independently split** reply frames, each its own control record. Sizes follow the H2 role (a SETTINGS-sized request → 33; a PING-sized one → 41; a HEADERS-scale one → a response-scale record; every index > 0 → 37 = WINDOW_UPDATE) and are **no longer derived from the request's payload length**, which would create a "request size → reply size" correlation. `M` is capped at **2**, down from 16: in H2 a PING/SETTINGS earns exactly one ACK, WINDOW_UPDATE earns none, and the only defensible second frame is the window update the receiver would send anyway.

> **The embedded default script no longer uses this mechanism** (every rule is `F:0`). `F:1` injected a PING/PING-ACK pair at data records 2 and 4, but a real H2 PING is a keepalive at 30–150 s intervals; firing two PING pairs within the connection's first few hundred milliseconds makes the frames *easier* to spot the more precisely PING-shaped they are, and landing one after a downstream burst forms `(−L4, L1, −L1)`. User scripts may still use `F:m` (it is not silently ignored), but configuration validation warns.
- Reply frames are never delivered to streams — discarded silently at the frame handler level (count as read activity for idle-timeout purposes).
- Junk bytes in both request and reply are zero; they sit on the plaintext side of the AEAD, so their content is invisible on the wire.

### 3.10 The Three-Layer Anti-TLS-in-TLS Structure

This section describes the mechanisms built against the USENIX Security 2024 encapsulated-TLS-handshake detector referenced throughout §9. The detector reads only the **first 25 data-carrying TCP packets after the outer handshake** and **judges a connection once, at birth** (§9.1).

#### Fidelity layer (inside the observation window)

- **The connection's first shaped data record** is drawn from `FIRST_RECORD_PAYLOAD_LO..HI` = 152..248 payload ⇒ 176..272 bytes on the wire, **strictly below 300**, and it preempts the traffic script (C2S only). It varies within the window rather than taking a fixed value: a real H2 first HEADERS size varies with the request, and a fixed value would trade one discriminator for a cross-connection constant integer.
- **`quiet_gap`: yield the direction after the first record.** A burst can only be broken by a direction change or a ≥3×RTT gap (§9.2), so the writer must genuinely go quiet — `wait_for_peer_turn` waits for peer arrival, bounded by `PEER_TURN_MAX_WAIT = 300 ms`. This is literally the paper's "buffer application data when the scheduler demands quiet time". Cost: +1 RTT once per tunnel connection (`packet_seq == 0` only), amortized by the pool. **C2S only**: Figure 8 measures the *client's* first burst, and making the server pause too is a shape nginx never produces.
- **On decoding the client's `CMD_SETTINGS` the server immediately emits the nginx/h2o opening flight** (§3.2), which the client answers with a 33-byte SETTINGS-ACK. This beats waiting for SYNACK (which needs DNS + connect, 10–100 ms) because it is a frame-layer reply and completes sub-RTT.
- **Synthetic co-existing flow engine**: the paper notes that multiplexing's effectiveness depends entirely on *active* co-existing flows, and that a single-flow connection is as exposed as a non-multiplexed proxy. The client therefore maintains a low-rate synthetic H2 request/response exchange (a HEADERS-sized control record, `m=1`, answered with a response-scale record): `U{1,2,3}` exchanges at ~30 ms median during the opening (landing inside the window), then browsing scale (~20 s median, heavy tail, capped at 300 s). Gated on: client direction, `!post_script_off`, **the peer has already spoken** (otherwise a synthetic request would join the first upstream burst and break the 300-byte bound), and either still inside the opening window or at least one stream open. That last gate is deliberate — a fully idle H2 connection *should* be torn down by the idle timeout, and keeping it alive artificially with dummy frames is itself a tell.

#### Permanent layer (whole connection lifetime, near-zero cost)

1. **Data records never land in `L1`** (wire ≤160). Both `markov_policy` and `script_policy` are bound by this; the latter is a hard clamp, because a configuration-time lint warning cannot un-send a record (§9.6).
2. **A record's size must not be a deterministic function of the backlog** — but **the exact tail of a genuine bulk run is faithful** (a real TLS write of 100 KB is 6 full records plus one exactly-sized tail). The boundary is the `bulk_run` predicate: when the same drain already emitted a full-capacity record, the tail only adds `n mod 16384`; without that prefix, `n mod 16384` **is** `n` — the inner protocol's message length. **This protects inner message length and is therefore not window-scoped.**
3. **Flush coalescing**: flush only when both the control and bulk channels are empty, otherwise merge into the next `write()`. Under TCP_NODELAY the flush boundary *is* the segment boundary, which is the unit the classifier observes; real NSS/BoringSSL drain everything nghttp2 has queued into a single `write()`. Measured to yield **no detectable gain** against the paper's features (§9.8); retained because it is closer to a real implementation.
4. **Records carrying `CMD_SYN` / `CMD_FIN` do not use the control discrete pool** (end of §3.2).

#### Post-window relaxation

Once the observation window has passed (measured as `flush count + inbound.arrivals()`, a **lower bound** on bidirectional data packets, so relaxation always starts later than the true window ends), `markov_policy`'s 15% log-normal delay injection decays linearly to zero over `POST_WINDOW_RELAX_BAND = 12` packets. What decays is the **Bernoulli trigger probability**, not `mu`/`sigma` — shape and location are constants in real implementations.

**A decay band is mandatory; a cliff is not acceptable**: shaping that stops abruptly at packet N leaves a distribution break at N±5, the same class of problem this project has already solved twice (the script blend window, the control-state opening sequence).

Measured benefit: 960 KB written in 8 KB chunks drops from 876 ms to 86 ms (~10×). **Medium-backlog size splitting is not relaxed**, for the reason in permanent-layer item 2.

---

### 3.9 Wire Record Size Reference

Every post-handshake record is a 0x17 record with a 5-byte header (`| 0x17 | 0x03 | 0x03 | len(u16 BE) |`) followed by Noise-encrypted ciphertext. Each plaintext carries: `[length_prefix(2B, BE) | payload | padding(zero) | inner_content_type(1B, 0x17)]`.

| Record Type | Wire Size (= 5 + cipher) | Sizing Control | Padding Source |
|---|---|---|---|
| Shaped data record | **shaper-dictated** (24–16406) | `TrafficShaper::next_data_policy` → `prepare_data_record(target_wire_len)` | Zero (RFC 8446 §5.4) |
| Control frame | discrete (33–82) or headed (124–824) → §3.2 | `control_size::next_control_size` → `prepare_control_record(payload, size)` | Zero |
| Flight3 CCS | **6** (unencrypted) | Hardcoded | — |
| Flight3 Finished ghost | **58** | 37 + 16 AEAD + 5 header | — |
| Flight3 H2 ghost | **86 / 92 / 98** | variant fixed **per process** (`OnceLock`), not per connection — see §9.12 | — |
| H2 GOAWAY (pre-teardown) | **41** (= `PING_WIRE`) | `H2_GOAWAY_WIRE`; the payload carries `last_stream_id`, wire size unchanged | Zero |
| Close notify alert | **24** (3 + 16 + 5) | Hardcoded `[01 00 15]` | — |
| Ghost record (server) | **5 + cache_size** | camouflage cache | Fresh CSPRNG, per connection |

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
| PADDING | 0x08 | Fake-response engine (§3.8); request/reply cover frames |

### 4.2 Pipelined Stream Open

Client stream open fuses `[SETTINGS] [SYN] [PSH(target)] [PSH(data)]` into one control-class coalesced write flush. The first stream on a fresh session defers its SYN via `DeferredUnsent` state — the SETTINGS frame (held in `PendingClientSettings`) and the SYN frame are buffered in the `Stream` object without being sent. On the first `write()` call, `write_gather_open()` takes the SETTINGS frame via `PendingClientSettingsGuard`, prepends it before the SYN, then appends target and data PSH frames. All are packed into a single `submit_write_packets` call with `FlushBehavior::Immediate`, producing one coalesced write flush.

The server validates the target, resolves DNS, and establishes the relay connection before issuing SYNACK. SYNACK thus confirms actual reachability — not just stream acceptance.

### 4.3 Idle Teardown

The session read loop (`run_read_loop`) uses a pinned `tokio::time::sleep` timer (`idle_timeout_secs`, default **75 s** from config, **without jitter**). On each successful read, the timer is reset to `now + idle_duration`. If the timer fires while no active streams, pending inbound streams, or pending open streams exist (`is_idle_timeout_eligible()`), the session tears down gracefully: a Noise-encrypted TLS `close_notify` alert (0x15) is sent, followed by TCP FIN. No application-layer heartbeat is sent — kernel TCP keepalive serves as dead-peer detection, with values matching **Firefox's defaults: 600 s idle, 1 s interval, 4 probes** (`network.tcp.keepalive.idle_time / retry_interval / probe_count`), **without jitter**: Firefox sets the same values on every socket, and per-connection jitter would give one client's connections differing keepalive periods, which a real browser never does.

The cost: the dead-peer detection window moves from ~150 s to ~604 s. A peer that vanishes without FIN/RST *while holding an active stream* hangs for ~10 minutes. Connections with no active stream are unaffected — the server's 75 s idle teardown and the client pool's idle drain reclaim them first.

**H2-layer liveness is separate** (§4.4): the client sends a `PING` after **58 s with no peer arrival** (Firefox's `network.http.spdy.ping-threshold` default); the server never initiates one (nginx does not) and only answers with PING-ACK. PING is **suppressed** while the connection is still inside the paper's observation window (the first 25 data-carrying packets) — a `(+41, −41)` pair there, landing after a downstream burst, forms `(−L4, L1, −L1)`.

**The client pool's idle drain is 115 s** (Firefox's `network.http.keep-alive.timeout` default; 115 rather than 120 because it sits just under the common 2-minute NAT state timeout), **without jitter**. The side that closes first is therefore the **server** (75 s), matching reality — a server usually closes an idle connection per its own `keepalive_timeout`.

The server's 75 s carries **no jitter** and is taken from nginx's `keepalive_timeout` default. It was previously 45 s ± 10%: the jitter violates principle 2 (a real nginx's `keepalive_timeout` is an exact constant), and 45 matches no real server's default. `keepalive_timeout` (75 s) is chosen over `http2_idle_timeout` (3 min) because the latter has been **obsolete since nginx 1.19.7** — the official documentation reads "This directive is obsolete since version 1.19.7. The `keepalive_timeout` directive should be used instead." ⇒ on any nginx a censor could compare against today, an idle H2 connection is governed by the 75 s value. 75 < 115 also preserves the invariant that the server is the side that closes first. The pool's `soft_ttl` is 3600 s, aligned with nginx's `keepalive_time` 1h default and the same semantics; its role is now a resource backstop rather than behavioural camouflage (under normal use a connection always disappears to idle or a server-initiated close first, leaving the value unobservable).

**The graceful teardown sequence on the wire is `[GOAWAY 41 B][close_notify 24 B]`**, two separate flushes, mirroring a real endpoint's `SSL_write` + `SSL_shutdown`. Previously only a close_notify was sent, with no control-sized record before it — yet a real nginx/Firefox always emits GOAWAY when closing an H2 connection. A minimum GOAWAY frame (9-byte header + 4 last_stream_id + 4 error_code = 17 bytes) is the same length as a PING, so `PING_WIRE = 41` is reused.

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

Every failure before Noise authentication is committed relays the client's traffic transparently to the camouflage endpoint. This is the *only* observable for input-driven failures, and it is uniform across all of them:

| Input | Observable |
|---|---|
| Non-TLS first record (`GET / HTTP/1.1`, …) | Transparent relay |
| Auth failure (bad PSK / MAC / replayed ClientHello) | Transparent relay |
| Missing SNI / SNI mismatch | Transparent relay |
| Record header declaring an oversized length | Transparent relay |
| Fewer than 5 bytes sent, or a stalled/partial record | Transparent relay of exactly the bytes that arrived |

Two properties matter for probe resistance:

- **The buffer handed to the relay contains only bytes the client actually sent.** An earlier implementation pre-filled the declared record length with zeros before reading, so a stalled ClientHello was forwarded upstream zero-padded to full length — the camouflage host then answered a request the client never made.
- **No input can flip the behavior.** Two earlier paths failed closed and were reachable with five bytes: an oversized declared length closed instantly (and, with unread data still queued, `close(2)` emitted RST rather than FIN), and sending nothing produced a silent FIN at exactly T+10.000 s. Both now relay.

The initial-record deadline is **two fixed constants**, chosen by whether any byte has arrived: **2 s** for zero bytes, **5 s** once a partial record exists (the latter measured from accept, so a fragmented ClientHello is not left with only 3 s).

**Randomization is deliberately avoided here.** A real nginx's `client_header_timeout` is an exact constant, so randomizing *our* timeout is itself a discriminator (§9.0, principle 2). The goal is not to make the timeout look random but to make it **unobservable**: after a read timeout the connection is relayed, so the close instant a prober measures is our timeout plus the upstream's; pushing our term far below the upstream's lets the upstream's real constant dominate and sinks our contribution below RTT noise. The earlier 8–15 s sampling was in **whole seconds** — it both added a measurable offset and had only 8 discrete values.

The relay itself propagates half-close in both directions (an unforwarded `shutdown(SHUT_WR)` would leave the upstream waiting out its own `keepalive_timeout`, which is distinguishable from a direct connection) and terminates only after 300 s with no traffic in either direction — far longer than a typical upstream idle timeout, so the upstream always closes first and this bound stays unobservable. It exists solely to stop permanently-silent connections from pinning permits and file descriptors.

Relaying is bounded:

| Limit | Value |
|---|---|
| Global concurrent fallbacks | 512 (fixed) |
| Per-IP concurrent fallbacks | 16 (fixed) |
| Fallback connect timeout | 3 s (fixed) |
| Concurrent in-handshake connections | 512 (fixed) |

**When a limit is exhausted** the connection cannot be relayed, and takes the single unified exit `emit_indistinguishable_close()`, which:

1. Drains the receive queue (bounded to 64 KiB / 200 ms) before closing, so the close is always a clean FIN. Without the drain, `close(2)` with unread data emits RST after the FIN, and that FIN-versus-FIN+RST split classifies the server from one connection based only on whether the prober sent anything.
2. Closes **immediately** after draining, with no delay.

   It previously slept a randomized 200–3000 ms. That delay violates principle 2: a real server does not close after a uniformly random delay. Aligning to `pre_auth_fallback_connect_timeout_secs` (3 s) is equally wrong — 3 s is *our* constant, not any nginx default (`proxy_connect_timeout` defaults to 60 s), and the two sub-paths that genuinely arrive here from "cannot reach upstream" have *already spent* those 3 seconds, so adding another yields 6 s; the remaining sub-paths (handshake limiter, fallback limiters, active-session limiter) never attempted upstream at all.

   The honest model is "the server has no capacity right now", and a real nginx under that model closes immediately after accept: when `worker_connections` is exhausted nginx accepts and then calls `ngx_close_accepted_connection()`, so the client observes a near-instant clean FIN. Side benefit: a rejected connection no longer holds an fd and a connection slot for 0.2–3 s while the server is *already* out of capacity — that was a positive feedback loop.

**The per-IP cumulative rate limiter has been removed.** The rule was "112 fallbacks per 3600 s window → 300 s cooldown", during which forwarding stopped. It had to go because it manufactured exactly what this section claims does not exist: no special input is needed, just **113 ordinary TCP connections** put that IP into a 300 s window in which every connection lands on the non-forwarding branch — and the exposed difference is **content-level** (connection 1 sending `GET / HTTP/1.1` receives the camouflage site's real HTTP response; connection 114 receives a silent close), which **no amount of close-posture shaping can hide**. The thresholds themselves are recoverable by binary search, and a real nginx has no default behaviour resembling "stop serving this IP for 300 s after N connections".

> **Stating the "a prober cannot trigger this branch" claim precisely.** This branch is reached only when a limiter is exhausted, and **no single connection's content** triggers it. It is not, however, unreachable: the per-IP concurrent fallback limit is 16, so a prober that opens and *holds* 16 slow fallback connections (the permit is returned only when the relay ends) sees the 17th land here. Compared with the removed cooldown the difference is one of kind — the cooldown was **persistent and stateful** (a stable 300 s sampling window), whereas the concurrency limit is **transient and load-dependent**, and the prober must simultaneously sustain 16 connections to the camouflage endpoint. The honest statement is: **triggering it requires a prober to occupy limiter slots, not to choose some input.** Those slots are **memoryless** — behaviour reverts the instant one frees, and the server keeps no cross-time state; the deleted cooldown, by contrast, sustained differing behaviour for 300 s after the prober had gone.
>
> One residual deserves recording honestly: **the per-IP concurrency cap is the one dimension here that does not fully align with a real nginx default.** nginx's `worker_connections` is global; `limit_conn` is the per-key one, but it is off by default and answers with a 503 page rather than a silent FIN. A prober holding 17 connections while using a second IP as a control really has found something. Both obvious mitigations trade one problem for another (raising 16 to 512 lets a single IP starve the global pool; dropping the per-IP cap is closer to nginx's global-exhaustion semantics but pushes *other* clients onto this branch), so the current shape is kept and recorded here.

## 6. Fingerprint-Specific Presets

The `fingerprint` config field selects the ClientHello generation strategy:

| Preset | Source | Cipher Suite Order | Key Share Groups |
|---|---|---|---|
| `firefox` | Captured bootstrap hex blob | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | X25519MLKEM768, X25519, SECP256R1 |

`firefox` is the only supported value (and the default); any other `fingerprint` value fails config validation. The preset preserves the captured record shape (extension order, padding, record length) exactly, with two load-time normalizations applied to every template (embedded or `template_path` custom hex alike):

1. **No extension is stripped.** The emitted extension-type list is **item-for-item identical**
   to the captured real Firefox — 15 of them:
   `0000 0017 ff01 000a 000b 0010 0005 0022 0012 0033 002b 000d 001c 001b fe0d`,
   and the ClientHello returns to 1884 bytes.

   A strip list `[0xFE0D, 0x014A, 0x0119, 0x001C, 0x0022]` previously removed
   `record_size_limit` (0x001C), `delegated_credentials` (0x0022) and ECH (0xFE0D) — 305 bytes —
   leaving a JA3/JA4 extension list that **matches no released Firefox** (15 extensions became 12).
   `0x0119` / `0x014A` do not exist in the template at all: they are a **parsing error** that walked
   the ECH header `fe 0d 01 19 | 00 00 01 00 01 4a 00 20 …` as if it were three extensions —
   `0x0119` = 281 is ECH's `extension_length`, and `0x014A` straddles `config_id=0x4a ‖ enc_len=0x0020`.
   The stripping machinery itself is retained (parameterized) as the only way to neutralize a
   hostile extension in a custom template.

2. **ECH is refreshed per connection, not stripped.** The capture carries a GREASE ECH
   (`type=0`, HPKE kdf/aead both `0x0001`). Replaying it verbatim would be a 281-byte
   cross-connection constant, so three fields are regenerated per connection:
   `config_id` (1 B) random, `enc` (32 B) **uniform random bytes**, `payload` (239 B) random;
   `type`, `cipher_suite` and **every length field** stay constant.

   `enc` must be random bytes and **not** a real X25519 public key — byte 31 of the captured
   `enc` has its MSB set, which is impossible for a real X25519 public key, proving NSS fills
   GREASE ECH `enc` with random bytes. See §9.5.

   ⚠️ Tightly coupled: `stable_client_hello_fingerprint` must normalize these three fields, or
   every connection yields a different fingerprint ⇒ the camouflage profile cache degenerates to
   one entry per connection ⇒ every client connection triggers a live fetch to the camouflage endpoint.

3. **One X25519 key per connection, written to both shares.** In a real Firefox the X25519 (0x001d)
   share and the trailing 32 bytes of the X25519MLKEM768 hybrid share are **byte-identical**
   (NSS 3.103, Bug 1902119). Generating an independent key for each creates a discriminator
   stronger than the one it removes (a single-connection, zero-false-positive 32-byte memcmp);
   filling with random bytes violates "a real public key always has its MSB clear". See §9.4.
2. **Structurally valid X25519MLKEM768 share**: per connection, the 1216-byte hybrid share is regenerated with 768 coefficients sampled uniformly from [0, 3329) (the genuine ML-KEM.768 ek distribution) plus random rho/X25519 bytes. ML-KEM-capable servers (OpenSSL 3.5+) validate coefficients on decode and alert `illegal_parameter` on random garbage; valid shares are also statistically indistinguishable from a real Firefox key.

A custom ClientHello hex file can override the embedded Firefox template via `template_path`; the same normalization applies.

---

## 7. Error Handling State Machine

Every branch that a prober can reach by choosing its input ends in transparent relay. The one exit that does not reach the camouflage endpoint is gated on limit exhaustion, which no input can trigger on demand.

```
                          TCP connection accepted
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ Handshake limiter has capacity?    │
                        └─────────────┬────────┬─────────────┘
                                  Yes │        │ No
                                      │        ▼
                                      │   emit_indistinguishable_close
                                      │   (drain, then FIN immediately)
                                      ▼
              Read initial record (2s zero-byte / 5s partial, both constant)
                                      │
                        ┌─────────────┴──────────────────────┐
                        │ Complete 0x16 record?              │
                        └─────────────┬────────┬─────────────┘
                                  Yes │        │ No — non-TLS type,
                                      │        │ oversized declared length,
                                      │        │ timeout, EOF, <5 bytes
                                      │        ▼
                                      │  Pre-Auth Fallback
                                      │  → transparent relay of exactly
                                      │    the bytes that arrived
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

Any Pre-Auth Fallback that cannot be established — global/per-IP concurrency exhausted, IP in cooldown, upstream unreachable — falls through to the same `emit_indistinguishable_close` shown at the top, so all limit-exhaustion outcomes share one observable (§5.2).

---

## 8. Session Configuration

The `session` block (optional, under `settings` in both client outbounds and server inbounds) controls per-session behavior:

| Field | Type | Default | Description |
|---|---|---|---|
| `max_streams_per_session` | usize | 256 | Maximum concurrent multiplexed streams per tunnel session. |
| `idle_timeout_secs` | u64 | 75 | Session idle teardown timeout — a **constant, no jitter** (nginx's `keepalive_timeout` default). |
| `traffic_script` | optional string array | (embedded default) | Declarative script controlling post-handshake data packets (§3.5): an optional `stop=N` entry plus indexed rules `i=L:lo-hi,D:d,F:f`. Rules are cycled with `packet_seq % N` until `stop`, then transition to the Markov machine via a 6-packet smooth blend window. Example: `["stop=4", "0=L:200-250,D:0,F:0", "1=L:300-400,D:2.0-0.5,F:0"]`. The first number in `D:` is the **median in milliseconds**. Malformed scripts trigger a non-fatal startup warning and fall back to the embedded default; five further semantic warnings (`F:m>0`, a rule that can land in `L1`, crossing an MTU, `stop` periodicity, `post_script_shaping="off"`) are described in §8. See `REFERENCE_TRAFFIC_SCRIPT` for a template. |
| `post_script_shaping` | optional string | `"markov"` | Post-script shaping mode (§3.5). `"markov"` (default): blend window → Markov machine. `"off"`: once the script is exhausted, records are emitted at their exact pending size with zero delay and no fake frames. Invalid values trigger a non-fatal startup warning and are treated as unset. |

The embedded default script (shown in `traffic_script` config syntax):
```
stop=6
0=L:200-250,D:0,F:0
1=L:180-220,D:1.5-0.6,F:0
2=L:250-350,D:0,F:0
3=L:300-400,D:2.0-0.5,F:0
4=L:200-300,D:0,F:0
5=L:400-600,D:3.0-0.7,F:0
```

> Rules 2 and 4 were previously `F:1`; all are now 0 (see §3.8).

### Semantics of `D:`

The first number in `D:` is the **median in milliseconds**, identically in both forms: `D:2.0` ≡ `D:2.0-0.5` (the latter states the log-space standard deviation explicitly). Internally `mu_ms = ln(median)` is stored.

The two-argument form previously took the first number **directly** as the log-space location parameter, so `D:1.5-0.6` had an actual median of `exp(1.5) = 4.48 ms` rather than 1.5 ms — transcribing the embedded default from this section's configuration syntax produced delays **3.0×** (`D:1.5-0.6`) to **6.7×** (`D:3.0-0.7`) longer than documented. The two forms are now unified.

Parse-time bounds were also added: median ∈ (0, 500] ms, sigma ∈ [0, 2.0]. The sigma bound is equally necessary — `D:2.0-5.0` has a legal median, but the normal tail can push a single sample to `e^20 ≈ 4.9×10⁸` times the median (days). Previously `D:1000-0.5` overflowed `exp(1000)` to `inf`, and `(inf * 1000.0) as u64` saturates in Rust to `u64::MAX` µs ≈ **584,000 years**, hanging the connection permanently.

### Semantic validation warnings

Beyond parsing, `validate_traffic_script` checks five classes of configuration that manufacture discriminators, each producing a non-fatal warning (deliberately **not** a parse failure — a parse failure falls back to the embedded default, which puts the deployment straight back into the "everyone runs the same default" population that a custom script exists to escape):

1. `F:m > 0` (see §3.8)
2. A rule whose randomized length can land in `L1`: the predicate is `len_lo ≤ 161`. Note that `randomize_script`'s ×0.85 scaling **truncates** via `as usize`, collapsing 161 onto the same value as 160 — **162 is the first safe value** (see §9.6)
3. A rule whose length can exceed one MTU segment (payload + 24 > ~1400)
4. `stop` far exceeding the rule count ⇒ periodic autocorrelation injected inside the observation window
5. `post_script_shaping = "off"` ⇒ past `stop`, plaintext length maps directly to wire length

### Reference script

`kanotls_config::script::REFERENCE_TRAFFIC_SCRIPT` provides one set of example values satisfying every constraint, together with a reproducible `tshark` derivation procedure (capture the first 25–30 application-data records of the real site you want to imitate after its outer handshake, convert with `payload = tls.record.length − 19`, fill `L:` from the p10–p90 quantiles and `D:` from the median inter-record gap).

**It is a template, not a canonical answer.** A script's value is **cross-deployment de-clustering** (§9.10) — if everyone copies this one it immediately becomes the new fleet signature, no better than the embedded default. The paper's discriminating quantities (first burst, burst structure, TCP segment boundaries, round-trip count) are guaranteed by hardcoded shaper logic and are **not script-controlled**: a wrong script only makes things worse, and a right one makes nothing better.

After the script rules are exhausted (with the smooth blend window bridging into the Markov machine), the TrafficShaper's Markov state machine (§3.4) governs sizing and delay for the remainder of the connection lifecycle. No configuration surface exists for the Markov transition parameters — they are derived from the pending backlog pressure via a probabilistic `p_bulk` ramp and are directionally symmetric.

---

## 9. Design Rationale Record: Judgements That Were Overturned

This section records judgements that **look correct but actively degrade camouflage**, together with the evidence that overturned them.

They are collected here because they share one property: intuition points the opposite way from the correct answer. In the implementation each amounts to a few unremarkable lines, but every one was established only after a real failed attempt. A maintainer who does not know these arguments is most likely to "fix" them straight back to the wrong side.

The detector referenced throughout is USENIX Security 2024, Xue et al., *Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes* (the "paper"), evaluated on live ISP traffic at an FPR aligned with the inferred GFW threshold.

### 9.0 Two Co-equal Principles

1. **Stably identifiable = blocked.** Any cross-connection constant that a `memcmp` can hit is fatal.
2. **Uniformly random = blocked.** If a real implementation holds a dimension **constant**, then randomizing that dimension is itself a discriminator.

The second is routinely overlooked, and more than half of the entries below stem from violating it. The only question that decides whether something should be randomized is: **does a real Firefox / nginx vary this?** — not "how do we make it more random".

### 9.1 The Detector Judges a Connection Once, at Birth

The paper's classifier requires observing both SYN and SYN-ACK, records only the **first 25 data-carrying TCP packets**, and discards flows shorter than that window.

⇒ **A tunnel connection is sampled exactly once and never again.** The dominant lever is therefore not how streams are distributed but **how many tunnel connections are ever created**: `P(detected) = 1 − (1−TPR)^N`. At TPR ≈ 0.15, N=1 → 15%, N=4 → 48%.

This redefines the connection pool's goal: **concentrating streams onto few long-lived connections is not a performance decision, it reduces the number of times we are sampled.** That is why `streams_per_connection_target` is `max_streams_per_session` rather than something smaller.

**It simultaneously opens a weakness.** A normal HTTPS connection performs exactly **one** TLS handshake in its life; a tunnel carrying 256 streams performs **256 inner handshakes** spread across its lifetime. Sliding the observation window to mid-flow costs a censor exactly what sampling the start costs. Each new stream's first data record must therefore receive the same protection as the connection's first data record — the two changes must ship together, or concentration amplifies exposure instead of reducing it.

### 9.2 A Burst Is Broken by a Direction Change **or** a ≥3×RTT Gap

Paper §6.2, verbatim: aggregate consecutive packets that "1) travel in the same direction and 2) have an inter-arrival time less than three times the estimated RTT".

An earlier reading held that only a direction change breaks a burst and timing does not count. Both conditions apply. The scheme that appeared to follow from this — replacing the direction change with a pause — is nevertheless wrong; see §9.7.

At a typical RTT of 20–200 ms the breaking threshold is **60–600 ms**, whereas the sane range for a traffic script's `D:` is 1–5 ms. So **`D:` changes the packet sequence (the 3-gram input) but breaks no burst (the Mahalanobis input)**.

### 9.3 The Five High-Distinctiveness 3-grams Must Not All Be Suppressed

The classifier's negative class is **ordinary TLS flows with the cover handshake stripped**. Ordinary HTTPS application data produces `(−L4,−L4,−L4)`, `(−L4,−L4,−L3)` and `(L2,−L4,−L4)` constantly — they are nothing but "request → MSS-segmented response → partial tail". The `Distinc.` column of the paper's Table 2 measures TLS-vs-non-TLS, not nested-handshake-vs-application-data.

Measurement confirmed this: an early implementation's downstream **never produced a full-MSS packet** — a 4 KB response came out as ~13 sub-MSS records. A TLS connection whose downstream never contains a 1460-byte segment is *more* anomalous than one that does.

The resulting policy:
- **Zero tolerance** only for the two that encode a *nested-handshake round trip*: `(L2,−L4,L1)` and `(−L4,L1,−L1)`. Both share the shape "large peer burst → small local packet", which ordinary HTTPS application data does not produce.
- A **reverse assertion** that a bulk download still produces `(−L4,−L4,−L4)`, guarding against over-shaping.

Both families of assertion live in `crates/session/src/session/tests.rs`; deleting either makes the other meaningless.

### 9.4 The Client's Two X25519 Shares Must Be the **Same** Key

In a real Firefox the X25519 (0x001d) share and the trailing 32 bytes of the X25519MLKEM768 hybrid share are **byte-identical** — NSS 3.103 (Bug 1902119), "reuse X25519 share when offering both X25519 and Xyber768d00". In the captured template those 32 bytes occur exactly twice, which verifies it directly.

Generating an independent real X25519 key for each position therefore creates a discriminator **stronger than the one it removes**: real Firefox always has them equal, we would always have them differ ⇒ a **single-connection, zero-false-positive 32-byte memcmp**.

Filling them with `fill_bytes` is equally wrong, but for the opposite reason: a real X25519 public key is a little-endian u-coordinate reduced mod 2^255−19, so its **most significant bit is always clear**, while random bytes set it half the time.

The correct behaviour is to derive **one** real key per connection and write it to both positions.

### 9.5 The GREASE ECH `enc` Field Should Precisely Be Random Bytes

The inverse of §9.4. In the captured Firefox ECH GREASE extension, byte 31 of `enc` has its **MSB set**, which is impossible for a genuine HPKE encapsulation key ⇒ NSS fills GREASE ECH `enc` with uniform random bytes.

So `fill_bytes` is required here and must **not** be "corrected" into a real key. `ech_grease_fields_are_uniform_random_not_x25519_keys` asserts that the MSB of `enc` is unbiased precisely so that such a "correction" turns CI red.

`config_id` (1 byte) and `payload` (239 bytes) are likewise refreshed per connection, but **every length field is held constant** — lengths are deterministically computed, and randomizing them would violate principle 2.

### 9.6 The L1-Safe Floor for a Script Rule Is `len_lo ≥ 162`, Not 161

`randomize_script` scales each rule's bounds by a per-connection `U[0.85, 1.20]`, the wire size is payload + `MIN_DATA_WIRE_LEN` (24), and L1 is the **closed** interval [1, 160]:

```
len_lo=160: 160×0.85=136.00 → as usize 136 → wire 160 → L1
len_lo=161: 161×0.85=136.85 → as usize 136 → wire 160 → L1   ← truncation
len_lo=162: 162×0.85=137.70 → as usize 137 → wire 161 → L2
```

The `as usize` truncation collapses 161 onto the same value as 160. **162 is the first safe value.**

A local L1-class record immediately following a large peer burst reproduces the highest-distinctiveness gram `(L2,−L4,L1)` exactly. Hence, beyond the configuration-time lint, `script_policy` also applies a **hard clamp** — a warning cannot un-send a record.

### 9.7 Replacing the Direction Change With a ≥3×RTT Pause Saves No Round Trip

The cheap filter is a conjunction, `RT < 2.5 AND FirstBurst < 300`, and suppressing the first burst relies on a direction change, which appears to raise RT. §9.2 seems to permit breaking the burst with a pause instead, adding no alternation.

**But the peer's reply is sent by the peer, whether or not we wait — that direction change happens regardless.** Substituting a timing gap saves exactly zero round trips and leaves RT unchanged, which was the scheme's only claimed benefit.

Further, the 3×RTT threshold is computed from the **censor's own** RTT estimate (taken from the TCP handshake) while ours would come from the tunnel handshake, so our pause might never reach it. A direction change is unconditional.

### 9.8 Coalescing Flush Boundaries Yields No Measurable Gain Against the Paper's Features

"Each small control record occupies its own TCP segment" looks like the root cause of both a high packet count and residual gram hits. A controlled measurement (40 connections per scenario, coalescing toggled on and off) showed total packet counts and in-window direction changes **all within round-to-round variance**.

The reason: in single-stream scenarios little is queued at the same instant anyway — write requests are naturally spread by RTT and application pacing. And the residual `(L2,−L4,L1)` seen with a zero-latency origin is caused by the **peer's kernel** coalescing the opening flight, SYNACK and response body into one large segment — our flush boundaries cannot change someone else's kernel.

The mechanism is nonetheless correct (genuinely co-queued content does merge) and closer to NSS/BoringSSL, so it is retained — but as fidelity, not as a win. By the same argument **coalescing does not reduce RT**: it only concatenates adjacent same-direction writes and never removes an alternation; with fewer packets a fixed 25-packet window spans more time, so alternations stay flat or rise.

### 9.9 Data and Control Records Are **Deliberately** Indistinguishable by Size

One argument once rested on the premise that "every record below roughly 194 bytes is unambiguously control-class". The premise is false: `markov_policy`'s `InteractiveControl` branch **deliberately** draws data-record sizes from the control-frame pool, and the bulk-hysteresis tail and `post_script_shaping = "off"` can both emit arbitrarily small data records.

An observer cannot cleanly partition control from data by size — **that is the design goal**. Any argument that depends on separating the two classes by size is invalid.

### 9.10 The Traffic Script's Role Is Fleet De-clustering, Not Structural Defence

The paper's discriminating quantities — first burst, burst structure, TCP segment boundaries, round-trip count — are **almost entirely governed by hardcoded shaper logic**: the connection's first-record size window preempts the script; the direction hand-over is supplied by the peer's H2 SETTINGS-ACK; everything past `stop` plus the blend window falls to a hardcoded truncated normal. Within the 25-packet window the script governs only a small slice.

The script's real value is **against population clustering**: if every deployment runs the same embedded default, that default's size/IAT distribution is itself a fittable fleet signature, and one fit hits every default deployment.

**It is double-edged.** A script helps only when the distribution you choose is *also* a real application's. Choosing one that matches no real application moves a deployment from "hidden in the crowd" to "a uniquely strange distribution".

Hence: **a reference script must exist as a template plus a derivation method** (see the doc comment on `kanotls_config::script::REFERENCE_TRAFFIC_SCRIPT`). If everyone copies it verbatim it immediately becomes the new fleet signature — no better than the embedded default.

### 9.11 Randomization Introduced to Mask a Constant Must Be Withdrawn When That Constant Is Removed

`emit_indistinguishable_close` used to sleep a random 200–3000 ms before closing. It was introduced for a reason: at the time "limiter exhausted" closed instantly and "read timeout" closed at a fixed instant, and those two measurable constants needed smoothing over.

Later fixes removed both constants themselves — every input-driven failure now relays transparently, and the read deadline was shortened until the upstream's own timeout dominates. **Once the thing being masked is gone, the mask itself becomes the only remaining feature**: a real server does not close after a uniformly random delay.

So whenever the X in "randomization introduced to mask X" is eliminated by some other fix, that randomization must be withdrawn with it. Otherwise it survives on the strength of having once been necessary, while its only remaining effect is to manufacture a discriminator in the sense of principle 2.

### 9.12 The Right Treatment for Hardcoded Values Is Alignment With a Real Source, Not Randomization

`FIRST_RECORD_PAYLOAD_LO/HI`, the distribution parameters of `next_data_record_payload`, `MARKOV_DELAY_SIGMA`, the H2 opening flight's size sequence, the WINDOW_UPDATE threshold, the PING idle threshold — all are globally uniform constants.

They **should** be constants (principle 2: a real implementation's sizing code is a compile-time constant). The question is therefore not whether to randomize them but: **does this hardcoded distribution look like some real implementation, or like nothing that exists?**

Every hardcoded value must therefore name a real source: Firefox's keepalive 600 s / 1 s / 4 probes, nginx's `keepalive_time 1h`, Firefox's `ping-threshold = 58 s`, Firefox's `kInitialRwin = 12 MiB` (the prototype of the connection window — scaled to 32 MiB with a 1/8-window WINDOW_UPDATE threshold so the stall-free rate `(window − threshold)/RTT` covers high-BDP links), the H2 SETTINGS / WINDOW_UPDATE / PING / GOAWAY frame sizes, and the 15 extensions of the captured Firefox ClientHello. **Global uniformity is not a defect here, provided what we are uniform with is real.**

For the same reason `H2_GHOST_VARIANTS` selects its variant **per process** rather than per connection: a real Firefox's SETTINGS are fixed at compile time, so every connection from one browser emits the same size, and per-connection jitter manufactures variance in a dimension that is genuinely constant. It is also **not** derived from the PSK — that would make an on-wire length a function of key material and collapse every client of a deployment onto one variant.
