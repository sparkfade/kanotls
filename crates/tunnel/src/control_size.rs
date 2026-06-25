use rand::distributions::WeightedIndex;
use rand::prelude::*;
use std::f64::consts::PI;

use crate::common::{AEAD_TAG_LEN, BLOCK_LEN_PREFIX_SIZE, INNER_CONTENT_TYPE_LEN, TLS_RECORD_HEADER_LEN};

const CONTROL_TLS_OVERHEAD: usize = TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN + INNER_CONTENT_TYPE_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Handshake,
    Transport,
}

impl ConnectionState {
    pub fn from_control_count(count: u64) -> Self {
        if count < 6 {
            ConnectionState::Handshake
        } else {
            ConnectionState::Transport
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDirection {
    C2S,
    S2C,
}

const WINDOW_UPDATE_WIRE: usize = 13 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const PING_WIRE: usize = 17 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const SETTINGS_ACK_WIRE: usize = 9 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const SETTINGS_SMALL_WIRE: usize = 27 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const SETTINGS_LARGE_WIRE: usize = 45 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;

const MERGED_SETTINGS_WU_SMALL_WIRE: usize = 40 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const MERGED_SETTINGS_WU_LARGE_WIRE: usize = 58 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const MERGED_SETTINGS_ACK_WU_WIRE: usize = 22 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const MERGED_PING_WU_WIRE: usize = 30 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;

fn handshake_pool() -> (&'static [usize], &'static [f64]) {
    static POOL: [usize; 7] = [
        SETTINGS_ACK_WIRE,
        SETTINGS_SMALL_WIRE,
        SETTINGS_LARGE_WIRE,
        MERGED_SETTINGS_WU_SMALL_WIRE,
        MERGED_SETTINGS_WU_LARGE_WIRE,
        MERGED_SETTINGS_ACK_WU_WIRE,
        WINDOW_UPDATE_WIRE,
    ];
    static WEIGHTS: [f64; 7] = [0.08, 0.25, 0.25, 0.14, 0.14, 0.10, 0.04];
    (&POOL, &WEIGHTS)
}

fn transport_discrete_pool() -> (&'static [usize], &'static [f64]) {
    static POOL: [usize; 5] = [
        WINDOW_UPDATE_WIRE,
        PING_WIRE,
        MERGED_PING_WU_WIRE,
        SETTINGS_ACK_WIRE,
        MERGED_SETTINGS_ACK_WU_WIRE,
    ];
    static WEIGHTS: [f64; 5] = [0.35, 0.25, 0.20, 0.10, 0.10];
    (&POOL, &WEIGHTS)
}

const HANDSHAKE_HEADERS_WEIGHT: f64 = 0.05;
const TRANSPORT_HEADERS_WEIGHT: f64 = 0.10;

struct TruncatedNormal {
    mean: f64,
    stddev: f64,
    lower: f64,
    upper: f64,
}

impl TruncatedNormal {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        loop {
            let u1: f64 = rng.gen_range(0.0..1.0);
            let u2: f64 = rng.gen_range(0.0..1.0);
            if u1 <= 0.0 {
                continue;
            }
            let z = (-2.0_f64 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
            let val = z * self.stddev + self.mean;
            if val >= self.lower && val <= self.upper {
                return val;
            }
        }
    }
}

fn headers_c2s_sampler() -> TruncatedNormal {
    TruncatedNormal {
        mean: 450.0,
        stddev: 120.0,
        lower: 250.0,
        upper: 800.0,
    }
}

fn headers_s2c_sampler() -> TruncatedNormal {
    TruncatedNormal {
        mean: 200.0,
        stddev: 50.0,
        lower: 100.0,
        upper: 400.0,
    }
}

fn single_wire_frame(h2_payload_bytes: usize) -> usize {
    h2_payload_bytes + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD
}

pub fn next_control_size(
    state: ConnectionState,
    direction: FlowDirection,
    rng: &mut impl Rng,
) -> usize {
    let (discrete_pool, discrete_weights) = match state {
        ConnectionState::Handshake => handshake_pool(),
        ConnectionState::Transport => transport_discrete_pool(),
    };

    let headers_weight = match state {
        ConnectionState::Handshake => HANDSHAKE_HEADERS_WEIGHT,
        ConnectionState::Transport => TRANSPORT_HEADERS_WEIGHT,
    };

    let discrete_total: f64 = discrete_weights.iter().sum::<f64>() + headers_weight;
    let discrete_threshold = 1.0 - headers_weight / discrete_total;

    if rng.gen::<f64>() < discrete_threshold {
        let dist = WeightedIndex::new(discrete_weights).expect("control size weights valid");
        discrete_pool[dist.sample(rng)]
    } else {
        let sampler = match direction {
            FlowDirection::C2S => headers_c2s_sampler(),
            FlowDirection::S2C => headers_s2c_sampler(),
        };
        let raw = sampler.sample(rng);
        let h2_payload = raw.round().clamp(sampler.lower, sampler.upper) as usize;
        single_wire_frame(h2_payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _WU_CHECK: () = assert!(WINDOW_UPDATE_WIRE == 37);
    const _PING_CHECK: () = assert!(PING_WIRE == 41);
    const _SA_CHECK: () = assert!(SETTINGS_ACK_WIRE == 33);
    const _SS_CHECK: () = assert!(SETTINGS_SMALL_WIRE == 51);
    const _SL_CHECK: () = assert!(SETTINGS_LARGE_WIRE == 69);
    const _MSWU_CHECK: () = assert!(MERGED_SETTINGS_WU_SMALL_WIRE == 64);
    const _MLWU_CHECK: () = assert!(MERGED_SETTINGS_WU_LARGE_WIRE == 82);
    const _MAWU_CHECK: () = assert!(MERGED_SETTINGS_ACK_WU_WIRE == 46);
    const _MPWU_CHECK: () = assert!(MERGED_PING_WU_WIRE == 54);

    #[test]
    fn wire_constants_match_spec() {
        let _ = WINDOW_UPDATE_WIRE;
        let _ = PING_WIRE;
        let _ = SETTINGS_ACK_WIRE;
        let _ = SETTINGS_SMALL_WIRE;
        let _ = SETTINGS_LARGE_WIRE;
        let _ = MERGED_SETTINGS_WU_SMALL_WIRE;
        let _ = MERGED_SETTINGS_WU_LARGE_WIRE;
        let _ = MERGED_SETTINGS_ACK_WU_WIRE;
        let _ = MERGED_PING_WU_WIRE;
    }

    #[test]
    fn handshake_pool_excludes_ping() {
        let (pool, _) = handshake_pool();
        assert!(!pool.contains(&PING_WIRE));
        assert!(!pool.contains(&MERGED_PING_WU_WIRE));
        assert!(pool.contains(&SETTINGS_SMALL_WIRE));
        assert!(pool.contains(&SETTINGS_LARGE_WIRE));
        assert!(pool.contains(&SETTINGS_ACK_WIRE));
        assert!(pool.contains(&MERGED_SETTINGS_WU_SMALL_WIRE));
        assert!(pool.contains(&MERGED_SETTINGS_WU_LARGE_WIRE));
        assert!(pool.contains(&MERGED_SETTINGS_ACK_WU_WIRE));
    }

    #[test]
    fn transport_pool_excludes_settings() {
        let (pool, _) = transport_discrete_pool();
        assert!(!pool.contains(&SETTINGS_SMALL_WIRE));
        assert!(!pool.contains(&SETTINGS_LARGE_WIRE));
        assert!(!pool.contains(&MERGED_SETTINGS_WU_SMALL_WIRE));
        assert!(!pool.contains(&MERGED_SETTINGS_WU_LARGE_WIRE));
        assert!(pool.contains(&WINDOW_UPDATE_WIRE));
        assert!(pool.contains(&PING_WIRE));
        assert!(pool.contains(&MERGED_PING_WU_WIRE));
    }

    #[test]
    fn next_control_size_handshake_returns_valid_sizes() {
        let mut rng = rand::thread_rng();
        for _ in 0..500 {
            let size = next_control_size(ConnectionState::Handshake, FlowDirection::C2S, &mut rng);
            assert!(size >= SETTINGS_ACK_WIRE, "size {} too small", size);
            assert!(size <= 800 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD, "size {} too large", size);
        }
    }

    #[test]
    fn next_control_size_transport_returns_valid_sizes() {
        let mut rng = rand::thread_rng();
        for _ in 0..500 {
            let size = next_control_size(ConnectionState::Transport, FlowDirection::S2C, &mut rng);
            assert!(size >= SETTINGS_ACK_WIRE, "size {} too small", size);
            assert!(size <= 800 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD, "size {} too large", size);
        }
    }

    #[test]
    fn headers_c2s_within_bounds() {
        let sampler = headers_c2s_sampler();
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let val = sampler.sample(&mut rng);
            assert!(val >= 250.0, "val {} < 250", val);
            assert!(val <= 800.0, "val {} > 800", val);
        }
    }

    #[test]
    fn headers_s2c_within_bounds() {
        let sampler = headers_s2c_sampler();
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let val = sampler.sample(&mut rng);
            assert!(val >= 100.0, "val {} < 100", val);
            assert!(val <= 400.0, "val {} > 400", val);
        }
    }

    #[test]
    fn connection_state_from_count() {
        assert_eq!(ConnectionState::from_control_count(0), ConnectionState::Handshake);
        assert_eq!(ConnectionState::from_control_count(3), ConnectionState::Handshake);
        assert_eq!(ConnectionState::from_control_count(5), ConnectionState::Handshake);
        assert_eq!(ConnectionState::from_control_count(6), ConnectionState::Transport);
        assert_eq!(ConnectionState::from_control_count(100), ConnectionState::Transport);
    }

    #[test]
    fn handshake_never_produces_ping() {
        let mut rng = rand::thread_rng();
        for _ in 0..2000 {
            let size = next_control_size(ConnectionState::Handshake, FlowDirection::C2S, &mut rng);
            assert_ne!(size, PING_WIRE, "handshake produced PING wire size");
            assert_ne!(size, MERGED_PING_WU_WIRE, "handshake produced PING+WU wire size");
        }
    }

    #[test]
    fn transport_never_produces_settings() {
        let mut rng = rand::thread_rng();
        for _ in 0..2000 {
            let size = next_control_size(ConnectionState::Transport, FlowDirection::S2C, &mut rng);
            assert_ne!(size, SETTINGS_SMALL_WIRE, "transport produced SETTINGS small size");
            assert_ne!(size, SETTINGS_LARGE_WIRE, "transport produced SETTINGS large size");
            assert_ne!(size, MERGED_SETTINGS_WU_SMALL_WIRE, "transport produced SETTINGS+WU small size");
            assert_ne!(size, MERGED_SETTINGS_WU_LARGE_WIRE, "transport produced SETTINGS+WU large size");
        }
    }
}
