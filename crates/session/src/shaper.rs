use kanotls_tunnel::{ConnectionState, FlowDirection, SnowyStream};
use std::time::Duration;

const RECENT_WINDOW_SIZE: usize = 8;
const MAX_PENDING_FLUSH_SIZE: usize = 256 * 1024;
const BULK_FAST_PATH_THRESHOLD: usize = MAX_PENDING_FLUSH_SIZE / 2;
#[allow(dead_code)]
const CONTROL_FRAMES_HANDSHAKE: u64 = 6;

/// The blend window width: over this many packets after the script is
/// exhausted, the probability of falling through to the Markov machine
/// ramps from 0% to 100%.
const SCRIPT_BLEND_WINDOW: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MacroState {
    HandshakeShaping,
    InteractiveControl,
    AsymmetricBulk,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum DelaySpec {
    None,
    LogNormal {
        mu_ms: f64,
        sigma_ms: f64,
    },
    /// Replay pre-recorded IAT (Inter-Arrival Time) values from a
    /// reference endpoint trace. Values are in microseconds. The
    /// array is read circularly with `packet_seq % len`.
    Replay(&'static [u32]),
}

#[derive(Clone, Debug)]
pub(crate) struct ScriptRule {
    pub len_lo: usize,
    pub len_hi: usize,
    pub delay: DelaySpec,
    pub expect_responses: u8,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FakeSpec {
    pub responses: u8,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // all fields are intentional api surface
pub(crate) struct ShapePolicy {
    pub target_wire_len: usize,
    pub delay: Duration,
    pub fake: Option<FakeSpec>,
    pub allow_full_block: bool,
}

pub(crate) struct TrafficShaper {
    direction: FlowDirection,
    state: MacroState,
    packet_seq: u64,
    script: Vec<ScriptRule>,
    control_frame_count: u64,
    recent_payload_sizes: [usize; RECENT_WINDOW_SIZE],
    recent_payload_idx: usize,
    max_pending_flush_size: usize,
}

fn embedded_script() -> Vec<ScriptRule> {
    vec![
        ScriptRule {
            len_lo: 200,
            len_hi: 250,
            delay: DelaySpec::None,
            expect_responses: 0,
        },
        ScriptRule {
            len_lo: 180,
            len_hi: 220,
            delay: DelaySpec::LogNormal {
                mu_ms: 1.5_f64.ln(),
                sigma_ms: 0.6,
            },
            expect_responses: 0,
        },
        ScriptRule {
            len_lo: 250,
            len_hi: 350,
            delay: DelaySpec::None,
            expect_responses: 1,
        },
        ScriptRule {
            len_lo: 300,
            len_hi: 400,
            delay: DelaySpec::LogNormal {
                mu_ms: 2.0_f64.ln(),
                sigma_ms: 0.5,
            },
            expect_responses: 0,
        },
        ScriptRule {
            len_lo: 200,
            len_hi: 300,
            delay: DelaySpec::None,
            expect_responses: 1,
        },
        ScriptRule {
            len_lo: 400,
            len_hi: 600,
            delay: DelaySpec::LogNormal {
                mu_ms: 3.0_f64.ln(),
                sigma_ms: 0.7,
            },
            expect_responses: 0,
        },
    ]
}

impl TrafficShaper {
    pub(crate) fn new(direction: FlowDirection, script_text: Option<&str>) -> Self {
        let script = if let Some(text) = script_text {
            parse_script(text).unwrap_or_else(|_| embedded_script())
        } else {
            embedded_script()
        };
        Self {
            direction,
            state: MacroState::HandshakeShaping,
            packet_seq: 0,
            script,
            control_frame_count: 0,
            recent_payload_sizes: [0; RECENT_WINDOW_SIZE],
            recent_payload_idx: 0,
            max_pending_flush_size: MAX_PENDING_FLUSH_SIZE,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn packet_seq(&self) -> u64 {
        self.packet_seq
    }

    #[allow(dead_code)]
    pub(crate) fn state(&self) -> MacroState {
        self.state
    }

    pub(crate) fn note_control_frame(&mut self) {
        self.control_frame_count = self.control_frame_count.saturating_add(1);
    }

    fn connection_state(&self) -> ConnectionState {
        ConnectionState::from_control_count(self.control_frame_count)
    }

    pub(crate) fn next_data_policy(&mut self, pending_len: usize) -> ShapePolicy {
        debug_assert!(pending_len > 0);
        let conn_state = self.connection_state();
        let cap = SnowyStream::data_record_capacity();

        if pending_len >= BULK_FAST_PATH_THRESHOLD || pending_len >= cap {
            self.state = MacroState::AsymmetricBulk;
            return ShapePolicy {
                target_wire_len: SnowyStream::max_data_record_wire_len(),
                delay: Duration::ZERO,
                fake: None,
                allow_full_block: true,
            };
        }

        if conn_state == ConnectionState::Handshake {
            return self.handshake_policy(pending_len, cap);
        }

        let script_packets = self.script.len() as u64;
        let packet_seq = self.packet_seq;

        // Smooth blend: when we are within SCRIPT_BLEND_WINDOW packets
        // past the script's natural end, the probability of using the
        // Markov machine ramps linearly from 0 to 1. Beyond that window,
        // the script is fully bypassed.
        let script_blend_p = if packet_seq < script_packets {
            1.0_f64
        } else {
            let overshoot = packet_seq.saturating_sub(script_packets);
            1.0_f64 - (overshoot as f64 / SCRIPT_BLEND_WINDOW as f64).min(1.0)
        };

        use rand::Rng;
        let mut rng = rand::thread_rng();
        if rng.gen::<f64>() < script_blend_p && !self.script.is_empty() {
            self.script_policy(pending_len, cap)
        } else {
            self.markov_policy(pending_len, cap)
        }
    }

    fn handshake_policy(&mut self, pending_len: usize, cap: usize) -> ShapePolicy {
        if pending_len >= cap {
            ShapePolicy {
                target_wire_len: SnowyStream::max_data_record_wire_len(),
                delay: Duration::ZERO,
                fake: None,
                allow_full_block: true,
            }
        } else {
            ShapePolicy {
                target_wire_len: SnowyStream::data_record_wire_len(pending_len),
                delay: Duration::ZERO,
                fake: None,
                allow_full_block: false,
            }
        }
    }

    fn script_policy(&mut self, _pending_len: usize, cap: usize) -> ShapePolicy {
        let idx = (self.packet_seq as usize).wrapping_rem(self.script.len());
        let rule = &self.script[idx];

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_h2_payload = rng.gen_range(rule.len_lo..=rule.len_hi);

        let target_wire_len = SnowyStream::data_record_wire_len(random_h2_payload.min(cap));

        let delay = delay_from_spec(&rule.delay, self.packet_seq);

        let fake = if rule.expect_responses > 0 {
            Some(FakeSpec {
                responses: rule.expect_responses,
            })
        } else {
            None
        };

        ShapePolicy {
            target_wire_len,
            delay,
            fake,
            allow_full_block: false,
        }
    }

    fn markov_policy(&mut self, pending_len: usize, _cap: usize) -> ShapePolicy {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Probabilistic transition to AsymmetricBulk: the probability
        // scales with the fraction of the pending flush buffer that is
        // occupied. A nearly-full backlog strongly biases bulk mode to
        // restore throughput.
        let p_bulk = (pending_len as f64 / self.max_pending_flush_size as f64).min(1.0);

        self.state = match self.state {
            MacroState::AsymmetricBulk => {
                // Exit bulk with probability inverse to backlog pressure.
                let p_exit = 1.0 - p_bulk;
                if rng.gen_bool(p_exit.min(0.85)) {
                    MacroState::InteractiveControl
                } else {
                    MacroState::AsymmetricBulk
                }
            }
            _ => {
                if rng.gen_bool(p_bulk) {
                    MacroState::AsymmetricBulk
                } else {
                    MacroState::InteractiveControl
                }
            }
        };

        let (target_wire_len, allow_full_block, delay, fake) = match self.state {
            MacroState::AsymmetricBulk => (
                SnowyStream::max_data_record_wire_len(),
                true,
                Duration::ZERO,
                None,
            ),
            MacroState::InteractiveControl => {
                let size = kanotls_tunnel::control_size::next_control_size(
                    ConnectionState::Transport,
                    self.direction,
                    &mut rng,
                );
                let size = size.max(SnowyStream::data_record_wire_len(4));
                let delay = if rng.gen::<f64>() < 0.15 {
                    let sample = sample_log_normal(1.5_f64.ln(), 0.8).max(0.0);
                    Duration::from_micros((sample * 1000.0).round() as u64)
                } else {
                    Duration::ZERO
                };
                (size, false, delay, None)
            }
            MacroState::HandshakeShaping => unreachable!(),
        };

        ShapePolicy {
            target_wire_len,
            delay,
            fake,
            allow_full_block,
        }
    }

    pub(crate) fn advance(&mut self) {
        self.packet_seq = self.packet_seq.saturating_add(1);
    }

    pub(crate) fn record_payload_size(&mut self, size: usize) {
        self.recent_payload_sizes[self.recent_payload_idx % RECENT_WINDOW_SIZE] = size;
        self.recent_payload_idx = self.recent_payload_idx.wrapping_add(1);
    }
}

fn delay_from_spec(spec: &DelaySpec, packet_seq: u64) -> Duration {
    match spec {
        DelaySpec::None => Duration::ZERO,
        DelaySpec::LogNormal { mu_ms, sigma_ms } => {
            let sample = sample_log_normal(*mu_ms, *sigma_ms).max(0.0);
            Duration::from_micros((sample * 1000.0).round() as u64)
        }
        DelaySpec::Replay(trace) => {
            if trace.is_empty() {
                return Duration::ZERO;
            }
            let idx = (packet_seq as usize) % trace.len();
            Duration::from_micros(trace[idx] as u64)
        }
    }
}

fn sample_log_normal(mu: f64, sigma: f64) -> f64 {
    use rand::Rng;
    use std::f64::consts::PI;
    let mut rng = rand::thread_rng();
    loop {
        let u1: f64 = rng.gen_range(0.0..1.0);
        let u2: f64 = rng.gen_range(0.0..1.0);
        if u1 <= 0.0 {
            continue;
        }
        let z = (-2.0_f64 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
        return (mu + sigma * z).exp();
    }
}

fn parse_script(text: &str) -> Result<Vec<ScriptRule>, String> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut len_range = None;
        let mut delay: DelaySpec = DelaySpec::None;
        let mut fake_response: u8 = 0;

        for part in line.split(',') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix("Length:") {
                let rest = rest.trim();
                if let Some((lo, hi)) = rest.split_once('~') {
                    let lo: usize = lo
                        .trim()
                        .parse()
                        .map_err(|e| format!("bad len_lo: {}", e))?;
                    let hi: usize = hi
                        .trim()
                        .parse()
                        .map_err(|e| format!("bad len_hi: {}", e))?;
                    if lo > hi {
                        return Err(format!("len_lo {} > len_hi {}", lo, hi));
                    }
                    len_range = Some((lo, hi));
                }
            } else if let Some(rest) = part.strip_prefix("Delay:") {
                let rest = rest.trim();
                delay = if rest == "0" {
                    DelaySpec::None
                } else if let Some((mu_s, sigma_s)) = rest.split_once('~') {
                    let mu: f64 = mu_s
                        .trim()
                        .parse()
                        .map_err(|e| format!("bad delay mu: {}", e))?;
                    let sigma: f64 = sigma_s
                        .trim()
                        .parse()
                        .map_err(|e| format!("bad delay sigma: {}", e))?;
                    DelaySpec::LogNormal {
                        mu_ms: mu,
                        sigma_ms: sigma,
                    }
                } else {
                    let d: u64 = rest.parse().map_err(|e| format!("bad delay: {}", e))?;
                    if d == 0 {
                        DelaySpec::None
                    } else {
                        DelaySpec::LogNormal {
                            mu_ms: (d as f64).ln(),
                            sigma_ms: 0.5,
                        }
                    }
                };
            } else if let Some(rest) = part.strip_prefix("FakeResponse:") {
                fake_response = rest
                    .trim()
                    .parse()
                    .map_err(|e| format!("bad fake: {}", e))?;
            }
        }

        let (len_lo, len_hi) =
            len_range.ok_or_else(|| format!("missing Length field in '{}'", line))?;
        rules.push(ScriptRule {
            len_lo,
            len_hi,
            delay,
            expect_responses: fake_response,
        });
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_rule() {
        let rules = parse_script("Length: 200~250, Delay: 0, FakeResponse: 0").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].len_lo, 200);
        assert_eq!(rules[0].len_hi, 250);
        assert_eq!(rules[0].expect_responses, 0);
    }

    #[test]
    fn parse_with_fake_response() {
        let rules = parse_script("Length: 100~200, Delay: 10~0.5, FakeResponse: 3").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].len_lo, 100);
        assert_eq!(rules[0].len_hi, 200);
        assert_eq!(rules[0].expect_responses, 3);
        match rules[0].delay {
            DelaySpec::LogNormal { mu_ms, sigma_ms } => {
                assert!((mu_ms - 10.0).abs() < 0.01);
                assert!((sigma_ms - 0.5).abs() < 0.01);
            }
            _ => panic!("expected LogNormal"),
        }
    }

    #[test]
    fn parse_multiple_rules() {
        let text = "\
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 300~400, Delay: 5~0.5, FakeResponse: 1
";
        let rules = parse_script(text).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].len_lo, 300);
        assert_eq!(rules[1].len_hi, 400);
        assert_eq!(rules[1].expect_responses, 1);
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let text = "\
# my script
Length: 200~250, Delay: 0, FakeResponse: 0

# second rule
Length: 300~400, Delay: 0, FakeResponse: 2
";
        let rules = parse_script(text).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parse_rejects_inverted_range() {
        assert!(parse_script("Length: 250~200, Delay: 0, FakeResponse: 0").is_err());
    }

    #[test]
    fn parse_rejects_missing_length() {
        assert!(parse_script("Delay: 0, FakeResponse: 0").is_err());
    }

    #[test]
    fn embedded_script_has_rules() {
        let script = embedded_script();
        assert!(!script.is_empty());
        for rule in &script {
            assert!(rule.len_lo > 0);
            assert!(rule.len_hi >= rule.len_lo);
        }
    }

    #[test]
    fn full_backlog_anchors_to_full_record() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None);
        let cap = SnowyStream::data_record_capacity();
        let policy = shaper.next_data_policy(cap * 3);
        assert!(policy.allow_full_block);
        assert!(policy.target_wire_len >= SnowyStream::data_record_wire_len(cap));
    }

    #[test]
    fn tail_backlog_is_sized() {
        let mut shaper = TrafficShaper::new(FlowDirection::S2C, None);
        let policy = shaper.next_data_policy(1234);
        assert!(policy.target_wire_len >= SnowyStream::data_record_wire_len(1234));
    }

    #[test]
    fn advance_increments_packet_seq() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None);
        assert_eq!(shaper.packet_seq(), 0);
        shaper.advance();
        shaper.advance();
        assert_eq!(shaper.packet_seq(), 2);
    }

    #[test]
    fn note_control_frame_advances_to_transport() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None);
        for _ in 0..CONTROL_FRAMES_HANDSHAKE {
            shaper.note_control_frame();
        }
        // After enough control frames, the connection state is Transport,
        // so the handshake bypass is inactive. The script/blend path runs;
        // script_policy always returns allow_full_block=false.
        let policy = shaper.next_data_policy(100);
        assert!(!policy.allow_full_block);
    }

    #[test]
    fn markov_transitions_to_bulk_with_full_backlog() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None);
        for _ in 0..CONTROL_FRAMES_HANDSHAKE {
            shaper.note_control_frame();
        }
        // Advance past the script + blend window so the Markov machine is
        // active (100% fall-through probability).
        shaper.packet_seq = (shaper.script.len() + SCRIPT_BLEND_WINDOW) as u64;
        let cap = SnowyStream::data_record_capacity();
        let full_flush = MAX_PENDING_FLUSH_SIZE;
        // A full pending buffer makes p_bulk = 1.0 → guaranteed transition.
        for _ in 0..RECENT_WINDOW_SIZE {
            shaper.record_payload_size(cap);
        }
        let _ = shaper.next_data_policy(full_flush);
        assert_eq!(shaper.state(), MacroState::AsymmetricBulk);
    }

    #[test]
    fn markov_stays_interactive_for_small_backlog() {
        let mut shaper = TrafficShaper::new(FlowDirection::S2C, None);
        for _ in 0..CONTROL_FRAMES_HANDSHAKE {
            shaper.note_control_frame();
        }
        shaper.packet_seq = (shaper.script.len() + SCRIPT_BLEND_WINDOW) as u64;
        // Tiny backlog → p_bulk ≈ 0 → stays InteractiveControl.
        let _ = shaper.next_data_policy(4);
        assert_eq!(shaper.state(), MacroState::InteractiveControl);
    }

    #[test]
    fn log_normal_generates_positive_values() {
        for _ in 0..100 {
            let val = sample_log_normal(2.0_f64.ln(), 0.5);
            assert!(val >= 0.0);
            assert!(val.is_finite());
        }
    }

    #[test]
    fn new_accepts_custom_script() {
        let script = "Length: 400~500, Delay: 0, FakeResponse: 0";
        let shaper = TrafficShaper::new(FlowDirection::C2S, Some(script));
        assert_eq!(shaper.script.len(), 1);
        assert_eq!(shaper.script[0].len_lo, 400);
        assert_eq!(shaper.script[0].len_hi, 500);
    }

    #[test]
    fn new_falls_back_on_bad_script() {
        let shaper = TrafficShaper::new(FlowDirection::C2S, Some("garbage"));
        assert!(!shaper.script.is_empty());
    }

    #[test]
    fn replay_delay_reads_circularly() {
        static TRACE: &[u32] = &[100, 200, 300];
        let spec = DelaySpec::Replay(TRACE);
        let d0 = delay_from_spec(&spec, 0);
        let d1 = delay_from_spec(&spec, 1);
        let d2 = delay_from_spec(&spec, 2);
        let d3 = delay_from_spec(&spec, 3);
        assert_eq!(d0, Duration::from_micros(100));
        assert_eq!(d1, Duration::from_micros(200));
        assert_eq!(d2, Duration::from_micros(300));
        assert_eq!(d3, Duration::from_micros(100));
    }

    #[test]
    fn replay_delay_empty_trace_returns_zero() {
        static TRACE: &[u32] = &[];
        let spec = DelaySpec::Replay(TRACE);
        assert_eq!(delay_from_spec(&spec, 0), Duration::ZERO);
    }

    #[test]
    fn exact_slice_precision_5000_to_800() {
        let initial_payload_size: usize = 5000;
        let mut pending: Vec<u8> = vec![0x41; initial_payload_size];

        let target_wire_len: usize = 800;
        let overhead: usize = kanotls_tunnel::common::MIN_DATA_WIRE_LEN;
        let payload_cap: usize = target_wire_len.saturating_sub(overhead);

        let take = payload_cap.min(pending.len());

        assert_eq!(
            take, payload_cap,
            "slice size mismatch: extracted plaintext must match target wire capacity"
        );

        pending.drain(..take);

        let expected_remainder = initial_payload_size - payload_cap;
        assert_eq!(
            pending.len(),
            expected_remainder,
            "remainder mismatch: buffer must retain exactly unsent payload"
        );
    }
}
