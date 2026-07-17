use kanotls_config::script::{parse_traffic_script, DelaySpec, ScriptRule};
use kanotls_tunnel::{ConnectionState, FlowDirection, SnowyStream};
use std::time::Duration;

const BULK_FAST_PATH_THRESHOLD: usize = crate::MAX_PENDING_FLUSH_SIZE / 2;

/// Per-connection randomization window for script rule lengths: each rule's
/// length bounds are scaled by an independent sample from U[0.85, 1.20].
const SCRIPT_LEN_SCALE_LO: f64 = 0.85;
const SCRIPT_LEN_SCALE_HI: f64 = 1.20;

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

#[derive(Clone, Copy, Debug)]
pub(crate) struct FakeSpec {
    pub responses: u8,
}

#[derive(Clone, Debug)]
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
    post_script_off: bool,
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
    pub(crate) fn new(direction: FlowDirection, script_text: Option<&str>, post_script_off: bool) -> Self {
        let mut script = if let Some(text) = script_text {
            parse_traffic_script(text).unwrap_or_else(|_| embedded_script())
        } else {
            embedded_script()
        };
        randomize_script(&mut script);
        Self {
            direction,
            state: MacroState::HandshakeShaping,
            packet_seq: 0,
            script,
            post_script_off,
        }
    }

    #[cfg(test)]
    pub(crate) fn packet_seq(&self) -> u64 {
        self.packet_seq
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> MacroState {
        self.state
    }

    pub(crate) fn next_data_policy(&mut self, pending_len: usize) -> ShapePolicy {
        debug_assert!(pending_len > 0);
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

        // Bulk hysteresis: the tail of a bulk burst goes out at its exact
        // size with zero delay and no fake frames — script/Markov delays
        // must not throttle the end of a throughput burst.
        if self.state == MacroState::AsymmetricBulk && pending_len < cap {
            self.state = MacroState::InteractiveControl;
            return ShapePolicy {
                target_wire_len: SnowyStream::data_record_wire_len(pending_len),
                delay: Duration::ZERO,
                fake: None,
                allow_full_block: false,
            };
        }

        // post_script_shaping = "off": once the script is exhausted, emit
        // every further record at its exact pending size with zero delay
        // and no fake frames — no Markov machine, no blend window.
        if self.post_script_off && self.packet_seq >= self.script.len() as u64 {
            return ShapePolicy {
                target_wire_len: SnowyStream::data_record_wire_len(pending_len),
                delay: Duration::ZERO,
                fake: None,
                allow_full_block: false,
            };
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
            self.script_policy(cap)
        } else {
            self.markov_policy(pending_len)
        }
    }

    fn script_policy(&mut self, cap: usize) -> ShapePolicy {
        let idx = (self.packet_seq as usize).wrapping_rem(self.script.len());
        let rule = &self.script[idx];

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_h2_payload = rng.gen_range(rule.len_lo..=rule.len_hi);

        let target_wire_len = SnowyStream::data_record_wire_len(random_h2_payload.min(cap));

        let delay = delay_from_spec(&rule.delay);

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

    fn markov_policy(&mut self, pending_len: usize) -> ShapePolicy {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Probabilistic transition to AsymmetricBulk: the probability
        // scales with the fraction of the pending flush buffer that is
        // occupied. A nearly-full backlog strongly biases bulk mode to
        // restore throughput.
        let p_bulk = (pending_len as f64 / crate::MAX_PENDING_FLUSH_SIZE as f64).min(1.0);

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
            // 不可达：上面的状态转移把 `_` 分支（含 HandshakeShaping）统一
            // 重新赋值为 AsymmetricBulk 或 InteractiveControl，执行到这里时
            // self.state 不可能仍是 HandshakeShaping。
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
}

fn delay_from_spec(spec: &DelaySpec) -> Duration {
    match spec {
        DelaySpec::None => Duration::ZERO,
        DelaySpec::LogNormal { mu_ms, sigma_ms } => {
            let sample = sample_log_normal(*mu_ms, *sigma_ms).max(0.0);
            Duration::from_micros((sample * 1000.0).round() as u64)
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

/// Per-connection randomization pass over a built script: rotate the rule
/// order by a random offset, then scale every rule's length window by an
/// independent U[SCRIPT_LEN_SCALE_LO, SCRIPT_LEN_SCALE_HI] sample (clamped
/// to >= 1, lo <= hi, hi <= data record capacity). This keeps the mapping
/// from "position i" to size distribution from being globally constant
/// across connections.
fn randomize_script(script: &mut [ScriptRule]) {
    use rand::Rng;
    if script.is_empty() {
        return;
    }
    let mut rng = rand::thread_rng();
    let offset = rng.gen_range(0..script.len());
    script.rotate_left(offset);
    let cap = SnowyStream::data_record_capacity();
    for rule in script.iter_mut() {
        let scale = rng.gen_range(SCRIPT_LEN_SCALE_LO..=SCRIPT_LEN_SCALE_HI);
        let lo = (rule.len_lo as f64 * scale) as usize;
        let hi = (rule.len_hi as f64 * scale) as usize;
        rule.len_lo = lo.max(1).min(cap);
        rule.len_hi = hi.max(rule.len_lo).min(cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_mark_value_stable_across_policies() {
        // A `?` rule is fixed at parse time: repeated policy calls must
        // yield the same target wire length.
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 100?50"), false);
        let first = shaper.next_data_policy(50);
        shaper.advance();
        let second = shaper.next_data_policy(50);
        assert_eq!(first.target_wire_len, second.target_wire_len);
        assert!(!first.allow_full_block);
    }

    #[test]
    fn randomize_script_keeps_bounds_valid() {
        let cap = SnowyStream::data_record_capacity();
        for _ in 0..50 {
            let shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
            assert_eq!(shaper.script.len(), 6);
            for rule in &shaper.script {
                assert!(rule.len_lo >= 1);
                assert!(rule.len_lo <= rule.len_hi);
                assert!(rule.len_hi <= cap);
            }
        }
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
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
        let cap = SnowyStream::data_record_capacity();
        let policy = shaper.next_data_policy(cap * 3);
        assert!(policy.allow_full_block);
        assert!(policy.target_wire_len >= SnowyStream::data_record_wire_len(cap));
    }

    #[test]
    fn fast_path_takes_priority_over_script() {
        let cap = SnowyStream::data_record_capacity();
        // Script rules never allow a full block; both fast-path thresholds
        // must win over the script from the very first data record.
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 500"), false);
        assert!(shaper.next_data_policy(BULK_FAST_PATH_THRESHOLD).allow_full_block);
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 500"), false);
        assert!(shaper.next_data_policy(cap).allow_full_block);
    }

    #[test]
    fn script_policy_applies_from_first_data_record() {
        // The handshake bypass is gone: packet_seq=0 must already consult
        // the script. The single fixed rule "Length: 500" is only scaled by
        // the randomization pass (U[0.85, 1.20]).
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 500"), false);
        assert_eq!(shaper.packet_seq(), 0);
        let policy = shaper.next_data_policy(100);
        assert!(!policy.allow_full_block);
        assert!(
            policy.target_wire_len >= SnowyStream::data_record_wire_len(425)
                && policy.target_wire_len <= SnowyStream::data_record_wire_len(600),
            "target {} outside randomized script window",
            policy.target_wire_len
        );
    }

    #[test]
    fn bulk_tail_uses_exact_size() {
        // Bulk hysteresis: the tail of a bulk burst (state=AsymmetricBulk,
        // pending < cap) is emitted at its exact wire length, with zero
        // delay and no fake frames, and the shaper leaves bulk mode.
        let mut shaper = TrafficShaper::new(FlowDirection::S2C, None, false);
        shaper.state = MacroState::AsymmetricBulk;
        let policy = shaper.next_data_policy(1234);
        assert_eq!(
            policy.target_wire_len,
            SnowyStream::data_record_wire_len(1234)
        );
        assert_eq!(policy.delay, Duration::ZERO);
        assert!(policy.fake.is_none());
        assert!(!policy.allow_full_block);
        assert_eq!(shaper.state(), MacroState::InteractiveControl);
    }

    #[test]
    fn off_mode_uses_script_until_exhausted() {
        // post_script_off does not disable the script itself: while
        // packet_seq < script.len(), script policy still applies. The
        // single fixed rule "Length: 500" is only scaled by the
        // randomization pass (U[0.85, 1.20]).
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 500"), true);
        assert_eq!(shaper.packet_seq(), 0);
        let policy = shaper.next_data_policy(100);
        assert!(!policy.allow_full_block);
        assert!(
            policy.target_wire_len >= SnowyStream::data_record_wire_len(425)
                && policy.target_wire_len <= SnowyStream::data_record_wire_len(600),
            "target {} outside randomized script window",
            policy.target_wire_len
        );
    }

    #[test]
    fn off_mode_exact_size_after_script() {
        // Once packet_seq reaches script.len(), off mode emits every record
        // at its exact pending size with zero delay and no fake frames —
        // no Markov machine, no blend window.
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 500"), true);
        shaper.packet_seq = shaper.script.len() as u64;
        for pending in [100usize, 1234, 4096] {
            let policy = shaper.next_data_policy(pending);
            assert_eq!(
                policy.target_wire_len,
                SnowyStream::data_record_wire_len(pending)
            );
            assert_eq!(policy.delay, Duration::ZERO);
            assert!(policy.fake.is_none());
            assert!(!policy.allow_full_block);
            shaper.advance();
        }
    }

    #[test]
    fn off_mode_fast_path_still_wins() {
        // The bulk fast path is checked before the off-mode branch and must
        // keep priority even after the script is exhausted.
        let cap = SnowyStream::data_record_capacity();
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 500"), true);
        shaper.packet_seq = shaper.script.len() as u64;
        assert!(shaper.next_data_policy(BULK_FAST_PATH_THRESHOLD).allow_full_block);
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some("Length: 500"), true);
        shaper.packet_seq = shaper.script.len() as u64;
        assert!(shaper.next_data_policy(cap).allow_full_block);
    }

    #[test]
    fn advance_increments_packet_seq() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
        assert_eq!(shaper.packet_seq(), 0);
        shaper.advance();
        shaper.advance();
        assert_eq!(shaper.packet_seq(), 2);
    }

    #[test]
    fn markov_transitions_to_bulk_with_full_backlog() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
        // Advance past the script + blend window so the Markov machine is
        // active (100% fall-through probability).
        shaper.packet_seq = (shaper.script.len() + SCRIPT_BLEND_WINDOW) as u64;
        let full_flush = crate::MAX_PENDING_FLUSH_SIZE;
        // A full pending buffer makes p_bulk = 1.0 → guaranteed transition.
        let _ = shaper.next_data_policy(full_flush);
        assert_eq!(shaper.state(), MacroState::AsymmetricBulk);
    }

    #[test]
    fn markov_stays_interactive_for_small_backlog() {
        let mut shaper = TrafficShaper::new(FlowDirection::S2C, None, false);
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
        let shaper = TrafficShaper::new(FlowDirection::C2S, Some(script), false);
        assert_eq!(shaper.script.len(), 1);
        // The randomization pass scales both bounds by one U[0.85, 1.20]
        // sample: lo stays within [340, 480], hi within [425, 600].
        assert!((340..=480).contains(&shaper.script[0].len_lo));
        assert!((425..=600).contains(&shaper.script[0].len_hi));
        assert!(shaper.script[0].len_lo <= shaper.script[0].len_hi);
    }

    #[test]
    fn new_falls_back_on_bad_script() {
        let shaper = TrafficShaper::new(FlowDirection::C2S, Some("garbage"), false);
        assert!(!shaper.script.is_empty());
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
