use rand::prelude::*;

use crate::common::{
    AEAD_TAG_LEN, BLOCK_LEN_PREFIX_SIZE, INNER_CONTENT_TYPE_LEN, MIN_DATA_WIRE_LEN,
    TLS_RECORD_HEADER_LEN,
};

const CONTROL_TLS_OVERHEAD: usize = TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN + INNER_CONTENT_TYPE_LEN;

/// 论文（USENIX Security 2024, Xue et al., *Fingerprinting Obfuscated Proxy
/// Traffic with Encapsulated TLS Handshakes*）离散化包尺寸时用的 `L1` 类上界：
/// 线速 1–160 字节。判别力最高的 3-gram `(L2, −L4, L1)`（Distinc 7.226）的第三
/// 个元素就是一个落在 `L1` 的**本端**包，语义是内层握手的
/// `client key exchange + ChangeCipherSpec`；`(−L4, L1, −L1)`（2.879）同样
/// 以「大的对端包 → 小的本端包」开头。
///
/// 该边界因此是**数据**记录尺寸的下界依据：真实 H2 端点在 `L1` 区间发出的是
/// 控制帧（SETTINGS-ACK 33 / WINDOW_UPDATE 37 / PING 41），承载 HEADERS 或
/// DATA 的记录不会这么小。KanoTLS 的控制记录已经覆盖了 `L1`，数据记录再落进
/// 去只会在「对端大 burst 之后」复现上面那两个 3-gram。
pub const L1_MAX_WIRE_LEN: usize = 160;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Handshake,
    Transport,
}

/// 开场（Handshake 态）控制记录的条数上界，跨方向取最大值。
///
/// 此前它是硬编码常量 6，且**前 6 条各自独立地从一个含 SETTINGS 的加权池
/// 里抽样**。这个模型本身就不是 HTTP/2：真实端点的开场控制帧序列是
/// **确定性**的，SETTINGS 只发一次、位置固定，发完 SETTINGS-ACK 之后
/// 永不再出现 SETTINGS。旧实现产出约 3 个 SETTINGS 族帧、位置随机、总数
/// 恒为 6 才切换，于是同时踩了两条线：
///
/// - 「一条 H2 连接发了三个位置随机的 SETTINGS」不是任何真实实现的行为；
/// - 「第 6 条之后 SETTINGS 尺寸消失」是一个跨连接、跨部署完全一致的整数。
///
/// 现改为按 `h2_opening_size` 给出的确定性序列取尺寸。**序列长度不做随机化**：
/// 真实 H2 的开场→稳态转换本来就是硬切换（发完 SETTINGS-ACK 就不再发
/// SETTINGS），硬边界在这里是保真而非缺陷；在真实实现恒定的维度上随机化，
/// 那份方差本身就是判别特征。
pub const H2_OPENING_MAX_LEN: u64 = 3;

impl ConnectionState {
    /// 开场序列是否尚未走完。
    ///
    /// 这里按方向无关的上界 `H2_OPENING_MAX_LEN` 判定，是有意偏保守的：
    /// C2S 的序列只有 1 条，于是 count = 1、2 时本函数仍报 Handshake。
    /// 精确的按方向序列由 `h2_opening_size` 决定，`SnowyStream::next_control_size`
    /// 在序列耗尽后自动落到 Transport 池，故多报一两条不影响任何线速尺寸。
    pub fn from_control_count(count: u64) -> Self {
        if count < H2_OPENING_MAX_LEN {
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

/// 判定一个线速尺寸是否属于「携带 SETTINGS 参数」的那一族——真实 H2 端点
/// 只在开场发一次，此后永不再现。
///
/// 接收端也用它做角色识别：一条 SETTINGS 尺寸的控制记录必须换来一条
/// SETTINGS-ACK（9 字节帧 ⇒ 33 字节记录），而不是 PING-ACK。
pub fn is_settings_bearing_wire_size(size: usize) -> bool {
    matches!(
        size,
        SETTINGS_SMALL_WIRE
            | SETTINGS_LARGE_WIRE
            | MERGED_SETTINGS_WU_SMALL_WIRE
            | MERGED_SETTINGS_WU_LARGE_WIRE
    )
}

/// 本进程 SETTINGS 帧携带的参数是否较多（决定 large / small 两档尺寸）。
///
/// 这是开场序列里**唯一**允许变化的部分，且逐**进程**固定而非逐连接抖动：
/// 真实端点的 SETTINGS 参数表是编译期常量（一个实现 = 一组固定的
/// SETTINGS），同一实例的每条连接都发完全相同尺寸的 SETTINGS。逐连接抖动
/// 会让「同一 IP 的不同连接携带不同数量的 SETTINGS 参数」，那本身就是判别
/// 信号——与 `client.rs` 的 `H2_GHOST_CONTEXT` 是同一个理由。
static H2_LARGE_SETTINGS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn h2_large_settings() -> bool {
    *H2_LARGE_SETTINGS.get_or_init(|| rand::thread_rng().gen_bool(0.5))
}

/// 开场序列中第 `index` 条控制记录的线速尺寸；`None` 表示序列已走完，
/// 之后一律走 Transport 稳态池。
///
/// **C2S（客户端方向，1 条）**：`preface + SETTINGS + WINDOW_UPDATE` 已经
/// 作为 Flight-3 的 H2 幽灵记录整体发出（§3.9 表里 86/92/98 那一行），所以
/// 控制记录流是从「收到对端 SETTINGS 后回的那一条 SETTINGS-ACK」开始的，
/// 开场只剩这 1 条。此后的连接级 WINDOW_UPDATE 由消费字节驱动，属于稳态
/// 行为，归 Transport 池（其中 WINDOW_UPDATE 权重 0.35 最高）。
///
/// **S2C（服务端方向，3 条）**：这就是真实 H2 服务端的开场——nginx / h2o
/// 先发自己的 SETTINGS，紧跟一条连接级 WINDOW_UPDATE（把默认的 65535
/// 初始窗口提到实际值），再对客户端的 SETTINGS 回一条 SETTINGS-ACK。
///
/// 两个方向此后都**永不再出现 SETTINGS 尺寸**：`TRANSPORT_POOL` 的支撑集
/// 已正确排除了 SETTINGS_SMALL / SETTINGS_LARGE 及其与 WINDOW_UPDATE 的
/// 合并变体（由 `transport_pool_excludes_settings` 断言）。
///
/// 尺寸选择纯属本地装饰，与协议兼容性无关：`prepare_control_record` 把明文
/// 零填充到目标线速尺寸，接收端只按帧内 2 字节长度前缀取回载荷，从不校验
/// 记录尺寸（见 `SnowyStream::poll_read` 的 `prefix_data_len` 分支）。因此
/// 本改动向后兼容，新旧客户端 / 服务端可任意互通。
pub fn h2_opening_size(direction: FlowDirection, index: u64) -> Option<usize> {
    match direction {
        // 客户端的 SETTINGS 与连接级 WINDOW_UPDATE 已在 Flight-3 幽灵记录里。
        FlowDirection::C2S => match index {
            0 => Some(SETTINGS_ACK_WIRE),
            _ => None,
        },
        FlowDirection::S2C => match index {
            0 => Some(if h2_large_settings() {
                SETTINGS_LARGE_WIRE
            } else {
                SETTINGS_SMALL_WIRE
            }),
            1 => Some(WINDOW_UPDATE_WIRE),
            2 => Some(SETTINGS_ACK_WIRE),
            _ => None,
        },
    }
}

pub const WINDOW_UPDATE_WIRE: usize = 13 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
pub const PING_WIRE: usize = 17 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
pub const SETTINGS_ACK_WIRE: usize = 9 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const SETTINGS_SMALL_WIRE: usize = 27 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const SETTINGS_LARGE_WIRE: usize = 45 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;

const MERGED_SETTINGS_WU_SMALL_WIRE: usize = 40 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const MERGED_SETTINGS_WU_LARGE_WIRE: usize = 58 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const MERGED_SETTINGS_ACK_WU_WIRE: usize = 22 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;
const MERGED_PING_WU_WIRE: usize = 30 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD;

static TRANSPORT_POOL_SIZES: [usize; 5] = [
    WINDOW_UPDATE_WIRE,
    PING_WIRE,
    MERGED_PING_WU_WIRE,
    SETTINGS_ACK_WIRE,
    MERGED_SETTINGS_ACK_WU_WIRE,
];
static TRANSPORT_POOL_WEIGHTS: [f64; 5] = [0.35, 0.25, 0.20, 0.10, 0.10];

const TRANSPORT_HEADERS_WEIGHT: f64 = 0.10;

/// 以与 `weights.iter().sum::<f64>()` 完全相同的顺序左折叠累加，因此常量
/// 求值结果与旧实现的运行期求和逐位（`to_bits()`）相等——采样分布不变。
const fn sum_weights(weights: &[f64]) -> f64 {
    let mut acc = 0.0f64;
    let mut i = 0;
    while i < weights.len() {
        acc += weights[i];
        i += 1;
    }
    acc
}

/// 走离散池（而非 HEADERS 截断正态）的机率门限，等价于旧实现的
/// `1.0 - headers_weight / (sum(discrete_weights) + headers_weight)`。
const fn discrete_threshold(weight_sum: f64, headers_weight: f64) -> f64 {
    1.0 - headers_weight / (weight_sum + headers_weight)
}

/// 一个状态对应的尺寸池。此前 `next_control_size` 每次调用都要把两个
/// **编译期常量**权重数组各求和一次（`discrete_total` 一次、进入离散分支后
/// `total` 又一次），而这个函数在每条控制记录上都被调用，属于热路径。
/// 现把两个和以及由它们导出的门限提为常量。
struct ControlPool {
    sizes: &'static [usize],
    weights: &'static [f64],
    weight_sum: f64,
    discrete_threshold: f64,
}

static TRANSPORT_POOL: ControlPool = ControlPool {
    sizes: &TRANSPORT_POOL_SIZES,
    weights: &TRANSPORT_POOL_WEIGHTS,
    weight_sum: sum_weights(&TRANSPORT_POOL_WEIGHTS),
    discrete_threshold: discrete_threshold(
        sum_weights(&TRANSPORT_POOL_WEIGHTS),
        TRANSPORT_HEADERS_WEIGHT,
    ),
};

struct TruncatedNormal {
    mean: f64,
    stddev: f64,
    lower: f64,
    upper: f64,
}

impl TruncatedNormal {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> f64 {
        loop {
            // Box-Muller 核心与 `utils::sample_log_normal` 共用（曾各存一份）；
            // 此处不复用对数正态版本——截断正态的变换是 `z·stddev + mean`，
            // 不取指数。
            let val = self.mean + self.stddev * crate::utils::sample_standard_normal();
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

/// 非 bulk 态**数据**记录的载荷下界：让线速尺寸恰好越过 `L1` 上界。
/// `data_record_wire_len(payload) = payload + MIN_DATA_WIRE_LEN`，因此
/// `payload = L1_MAX_WIRE_LEN + 1 - MIN_DATA_WIRE_LEN` 是最小的 `L2` 载荷。
pub const MIN_DATA_RECORD_PAYLOAD: usize = L1_MAX_WIRE_LEN + 1 - MIN_DATA_WIRE_LEN;

/// 非 bulk 态数据记录的载荷上界：整条记录仍装进一个 1500 字节 MTU 的分段
/// （`1400 + MIN_DATA_WIRE_LEN = 1424`）。这不是任意取值——延迟敏感的真实
/// 端点（nginx `ssl_buffer_size 4k`/1400、Cloudflare 的动态 record sizing）
/// 正是把 record 压在「一个分段」这个边界上；更大的 record 由 bulk 态给出，
/// 那对应 `ssl_buffer_size` 默认 16k 的形态。
const MAX_DATA_RECORD_PAYLOAD: usize = 1400;

/// 非 bulk 态数据记录的载荷分布。
///
/// 此前 `TrafficShaper` 的 `InteractiveControl` 直接复用
/// `next_control_size(Transport, …)`，于是数据记录例行落在离散控制池
/// `{33, 37, 41, 46, 54}`（约 91% 概率）——线速 33–54 字节，全部在 `L1`。
/// 那既复现了 `(L2, −L4, L1)` / `(−L4, L1, −L1)` 两个判别力最高的 3-gram，
/// 也不是任何 H2 端点的行为：一条 4 KB 的响应被切成十几条 33–54 字节的
/// application-data 记录，中途夹在响应体里的 41 字节 record 在真实 TLS 里
/// 根本不存在。
///
/// 方向不对称的理由与 `headers_*_sampler` 相反：请求侧的非 bulk 记录以
/// **请求头**为主（Cookie/UA 撑到数百字节，与 C2S HEADERS 同量级），响应侧
/// 的非 bulk 记录是**响应头 + 首个 DATA 帧**，因此均值更高。
///
/// 分布参数刻意**逐进程/逐连接恒定**：一个真实实现的 record 切分代码是编译期
/// 常量，同一实例的每条连接产出同一个尺寸分布。在这里叠加逐连接抖动等于在
/// 真实实现恒定的维度上引入方差，那份方差本身就是判别特征。
fn data_record_sampler(direction: FlowDirection) -> TruncatedNormal {
    let (mean, stddev) = match direction {
        FlowDirection::C2S => (450.0, 250.0),
        FlowDirection::S2C => (700.0, 400.0),
    };
    TruncatedNormal {
        mean,
        stddev,
        lower: MIN_DATA_RECORD_PAYLOAD as f64,
        upper: MAX_DATA_RECORD_PAYLOAD as f64,
    }
}

/// 采样一条 H2 `HEADERS` 帧尺寸的控制记录线速尺寸。
///
/// 这一档本来就在 `next_control_size` 的混合分布里（权重 0.10），但那里是「离散
/// 控制池 ∪ HEADERS 档」的混合抽样，调用方拿不到单独的 HEADERS 档。合成的 H2
/// 请求/响应交换（"synthetic co-existing flows"）需要的正是这一档：一条请求记录
/// 必须是 HEADERS 量级而不是 PING 量级，否则「小的本端包 → 小的对端包」紧跟在
/// 下行 burst 之后就等于论文 Distinc 2.879 的 `(−L4, L1, −L1)`。
pub fn next_headers_frame_wire_len(direction: FlowDirection, rng: &mut impl Rng) -> usize {
    let sampler = match direction {
        FlowDirection::C2S => headers_c2s_sampler(),
        FlowDirection::S2C => headers_s2c_sampler(),
    };
    let raw = sampler.sample(rng);
    let h2_payload = raw.round().clamp(sampler.lower, sampler.upper) as usize;
    single_wire_frame(h2_payload)
}

/// 采样一条非 bulk 数据记录的**载荷**字节数；调用方用
/// `SnowyStream::data_record_wire_len` 换算线速尺寸。
pub fn next_data_record_payload(direction: FlowDirection, rng: &mut impl Rng) -> usize {
    let sampler = data_record_sampler(direction);
    sampler
        .sample(rng)
        .round()
        .clamp(sampler.lower, sampler.upper) as usize
}

pub fn next_control_size(
    state: ConnectionState,
    direction: FlowDirection,
    rng: &mut impl Rng,
) -> usize {
    let pool = match state {
        // Handshake 态只是开场别名：开场序列完全由 `SnowyWriteHalf::
        // next_control_size` 里的 `h2_opening_size` 逐条决定（见
        // `H2_OPENING_MAX_LEN`），序列耗尽后一律与本池同分布。
        ConnectionState::Handshake | ConnectionState::Transport => &TRANSPORT_POOL,
    };

    if rng.gen::<f64>() < pool.discrete_threshold {
        // The pools hold only 5-7 constant entries, so a cumulative-weight
        // linear scan is cheaper than rebuilding a WeightedIndex (which
        // heap-allocates) for every control frame.
        let mut roll = rng.gen::<f64>() * pool.weight_sum;
        let mut idx = pool.weights.len() - 1;
        for (i, &weight) in pool.weights.iter().enumerate() {
            if roll < weight {
                idx = i;
                break;
            }
            roll -= weight;
        }
        pool.sizes[idx]
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
    fn transport_pool_excludes_settings() {
        let pool = TRANSPORT_POOL.sizes;
        assert!(!pool.contains(&SETTINGS_SMALL_WIRE));
        assert!(!pool.contains(&SETTINGS_LARGE_WIRE));
        assert!(!pool.contains(&MERGED_SETTINGS_WU_SMALL_WIRE));
        assert!(!pool.contains(&MERGED_SETTINGS_WU_LARGE_WIRE));
        assert!(pool.contains(&WINDOW_UPDATE_WIRE));
        assert!(pool.contains(&PING_WIRE));
        assert!(pool.contains(&MERGED_PING_WU_WIRE));
    }

    #[test]
    fn next_control_size_transport_returns_valid_sizes() {
        let mut rng = rand::thread_rng();
        for _ in 0..500 {
            let size = next_control_size(ConnectionState::Transport, FlowDirection::S2C, &mut rng);
            assert!(size >= SETTINGS_ACK_WIRE, "size {} too small", size);
            assert!(
                size <= 800 + BLOCK_LEN_PREFIX_SIZE + CONTROL_TLS_OVERHEAD,
                "size {} too large",
                size
            );
        }
    }

    // Handshake 态退役旧加权池后只是 Transport 的别名（开场序列由
    // `h2_opening_size` 单独保证，见 `h2_opening_sequence_*`）：任何取值都
    // 不得再携带 SETTINGS 尺寸——那是旧 HANDSHAKE_POOL 的支撑集。
    #[test]
    fn handshake_alias_never_produces_settings() {
        let mut rng = rand::thread_rng();
        for _ in 0..2000 {
            let size = next_control_size(ConnectionState::Handshake, FlowDirection::S2C, &mut rng);
            assert!(
                !is_settings_bearing_wire_size(size),
                "handshake alias produced SETTINGS wire size {}",
                size
            );
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

    // 边界从旧的常量 6 改为 `H2_OPENING_MAX_LEN`：开场序列不再是「6 条加权
    // 抽样」，而是最长 3 条的确定性 H2 开场（S2C: SETTINGS → WINDOW_UPDATE
    // → SETTINGS-ACK）。
    #[test]
    fn connection_state_from_count() {
        assert_eq!(
            ConnectionState::from_control_count(0),
            ConnectionState::Handshake
        );
        assert_eq!(
            ConnectionState::from_control_count(H2_OPENING_MAX_LEN - 1),
            ConnectionState::Handshake
        );
        assert_eq!(
            ConnectionState::from_control_count(H2_OPENING_MAX_LEN),
            ConnectionState::Transport
        );
        assert_eq!(
            ConnectionState::from_control_count(100),
            ConnectionState::Transport
        );
        // 上界必须覆盖最长方向（S2C）的实际序列长度，否则最后一条开场记录
        // 会被误判成稳态。
        assert_eq!(
            opening_sequence(FlowDirection::S2C).len() as u64,
            H2_OPENING_MAX_LEN
        );
    }

    #[test]
    fn transport_never_produces_settings() {
        let mut rng = rand::thread_rng();
        for _ in 0..2000 {
            let size = next_control_size(ConnectionState::Transport, FlowDirection::S2C, &mut rng);
            assert_ne!(
                size, SETTINGS_SMALL_WIRE,
                "transport produced SETTINGS small size"
            );
            assert_ne!(
                size, SETTINGS_LARGE_WIRE,
                "transport produced SETTINGS large size"
            );
            assert_ne!(
                size, MERGED_SETTINGS_WU_SMALL_WIRE,
                "transport produced SETTINGS+WU small size"
            );
            assert_ne!(
                size, MERGED_SETTINGS_WU_LARGE_WIRE,
                "transport produced SETTINGS+WU large size"
            );
        }
    }

    // P7 回归：提为常量的权重和必须与旧实现的运行期 `iter().sum()` 逐位
    // 相等，否则采样分布会发生（微小但真实的）漂移。
    #[test]
    fn hoisted_weight_sums_are_bit_identical_to_runtime_sums() {
        let transport_runtime: f64 = TRANSPORT_POOL_WEIGHTS.iter().sum();
        assert_eq!(
            TRANSPORT_POOL.weight_sum.to_bits(),
            transport_runtime.to_bits()
        );

        let transport_threshold =
            1.0 - TRANSPORT_HEADERS_WEIGHT / (transport_runtime + TRANSPORT_HEADERS_WEIGHT);
        assert_eq!(
            TRANSPORT_POOL.discrete_threshold.to_bits(),
            transport_threshold.to_bits()
        );
    }

    #[test]
    fn pool_arrays_stay_aligned() {
        assert_eq!(TRANSPORT_POOL.sizes.len(), TRANSPORT_POOL.weights.len());
    }

    fn opening_sequence(direction: FlowDirection) -> Vec<usize> {
        let mut sizes = Vec::new();
        let mut index = 0u64;
        while let Some(size) = h2_opening_size(direction, index) {
            sizes.push(size);
            index += 1;
        }
        sizes
    }

    // C3 回归（核心）：开场序列必须是**确定性**的。旧实现让前 6 条控制记录
    // 各自从含 SETTINGS 的加权池独立抽样，位置随机——真实 H2 端点的开场
    // 帧序列是固定的。
    #[test]
    fn h2_opening_sequence_is_deterministic() {
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            let baseline = opening_sequence(direction);
            for _ in 0..64 {
                assert_eq!(
                    opening_sequence(direction),
                    baseline,
                    "{:?} opening sequence varied between connections",
                    direction
                );
            }
        }
    }

    // 序列长度不做随机化，且不超过 `from_control_count` 用的上界。
    #[test]
    fn h2_opening_sequence_lengths_are_fixed() {
        assert_eq!(opening_sequence(FlowDirection::C2S).len(), 1);
        assert_eq!(opening_sequence(FlowDirection::S2C).len(), 3);
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            assert!(
                h2_opening_size(direction, H2_OPENING_MAX_LEN).is_none(),
                "{:?} opening exceeds H2_OPENING_MAX_LEN",
                direction
            );
        }
    }

    // 序列形状必须对应真实 H2 开场：
    // C2S 只剩 SETTINGS-ACK（preface + SETTINGS + WINDOW_UPDATE 已在 Flight-3
    // 幽灵记录里）；S2C 是 nginx/h2o 的 SETTINGS → WINDOW_UPDATE → SETTINGS-ACK。
    #[test]
    fn h2_opening_sequence_matches_real_h2_shape() {
        assert_eq!(
            opening_sequence(FlowDirection::C2S),
            vec![SETTINGS_ACK_WIRE]
        );

        let s2c = opening_sequence(FlowDirection::S2C);
        assert!(
            s2c[0] == SETTINGS_SMALL_WIRE || s2c[0] == SETTINGS_LARGE_WIRE,
            "server must open with its own SETTINGS, got {}",
            s2c[0]
        );
        assert_eq!(s2c[1], WINDOW_UPDATE_WIRE);
        assert_eq!(s2c[2], SETTINGS_ACK_WIRE);

        // 开场里绝不能出现 PING 族尺寸：真实端点不会用 PING 开场。
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            for size in opening_sequence(direction) {
                assert_ne!(size, PING_WIRE, "{:?} opening contains PING", direction);
                assert_ne!(
                    size, MERGED_PING_WU_WIRE,
                    "{:?} opening contains PING+WU",
                    direction
                );
            }
        }
    }

    // 开场之后 SETTINGS 尺寸必须彻底消失——真实 H2 发完 SETTINGS-ACK 就
    // 再也不发 SETTINGS。稳态池两个方向都必须满足。
    #[test]
    fn settings_sizes_never_appear_after_the_opening() {
        let mut rng = rand::thread_rng();
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            for _ in 0..4000 {
                let size = next_control_size(ConnectionState::Transport, direction, &mut rng);
                assert!(
                    !is_settings_bearing_wire_size(size),
                    "{:?} steady state emitted SETTINGS wire size {}",
                    direction,
                    size
                );
            }
        }
    }

    // C24 回归（核心）：非 bulk 数据记录的线速尺寸必须整体越过论文的 `L1`
    // 上界。`L1` 区间在真实 H2 里只属于控制帧；数据记录落进去就复现了判别力
    // 第 1（(L2,−L4,L1)，7.226）与第 3（(−L4,L1,−L1)，2.879）两个 3-gram 的
    // 「大对端包 → 小本端包」结构。
    #[test]
    fn data_records_never_fall_into_the_l1_size_class() {
        let mut rng = rand::thread_rng();
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            for _ in 0..4000 {
                let payload = next_data_record_payload(direction, &mut rng);
                let wire = payload + MIN_DATA_WIRE_LEN;
                assert!(
                    wire > L1_MAX_WIRE_LEN,
                    "{:?} data record wire {} fell into L1",
                    direction,
                    wire
                );
                // 上界：一条记录仍装进一个 MTU 分段。
                assert!(wire <= MAX_DATA_RECORD_PAYLOAD + MIN_DATA_WIRE_LEN);
            }
        }
    }

    // 合成 H2 交换的请求记录必须是 HEADERS 量级：越过 `L1` 上界、且落在
    // `next_control_size` 的 HEADERS 档区间内（两处必须是同一个分布，否则合成
    // 请求会在控制记录的尺寸分布里形成一个可分离的第二峰）。
    #[test]
    fn headers_frame_sizes_clear_l1_and_match_the_control_headers_band() {
        let mut rng = rand::thread_rng();
        for (direction, sampler) in [
            (FlowDirection::C2S, headers_c2s_sampler()),
            (FlowDirection::S2C, headers_s2c_sampler()),
        ] {
            let lo = single_wire_frame(sampler.lower as usize);
            let hi = single_wire_frame(sampler.upper as usize);
            let mut seen = std::collections::HashSet::new();
            for _ in 0..2000 {
                let wire = next_headers_frame_wire_len(direction, &mut rng);
                // 只有 C2S 需要整体越过 L1：合成交换的**请求**走这一档，落进 L1
                // 就等于用一个 PING 量级的小包去换应答。S2C 这一档是**响应头**，
                // 真实 H2 里它本来就可以只有一百来字节；而合成交换的应答不走这
                // 一档（走 `next_data_record_payload`，恒 > L1）。
                if direction == FlowDirection::C2S {
                    assert!(
                        wire > L1_MAX_WIRE_LEN,
                        "C2S HEADERS 记录 {} 落在 L1",
                        wire
                    );
                }
                assert!((lo..=hi).contains(&wire), "{:?} HEADERS 记录 {} 越界", direction, wire);
                seen.insert(wire);
            }
            assert!(seen.len() > 20, "{:?} HEADERS 尺寸必须是分布而不是常量", direction);
        }
    }

    // 数据记录尺寸必须**分布**而不是常量：真实 H2 的 HEADERS/DATA 记录尺寸
    // 随请求与响应变化，取定值会换来一个跨连接稳定的整数。
    #[test]
    fn data_record_payloads_are_not_a_constant() {
        let mut rng = rand::thread_rng();
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            let mut seen = std::collections::HashSet::new();
            for _ in 0..200 {
                seen.insert(next_data_record_payload(direction, &mut rng));
            }
            assert!(seen.len() > 20, "{:?} sizes too concentrated", direction);
        }
    }

    // 数据记录的尺寸分布与控制记录的离散池必须**不相交**：两类记录在真实 H2
    // 里对应不同的帧族（HEADERS/DATA vs SETTINGS/PING/WINDOW_UPDATE），共用
    // 同一支撑集就等于让数据记录冒充控制帧。
    #[test]
    fn data_record_sizes_are_disjoint_from_the_control_discrete_pool() {
        let mut rng = rand::thread_rng();
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            for _ in 0..2000 {
                let wire = next_data_record_payload(direction, &mut rng) + MIN_DATA_WIRE_LEN;
                assert!(
                    !TRANSPORT_POOL_SIZES.contains(&wire),
                    "{:?} data record wire {} collides with a control pool size",
                    direction,
                    wire
                );
            }
        }
    }

    // SETTINGS 参数档位（small/large）是进程常量：真实端点的 SETTINGS 内容
    // 由代码决定，逐连接抖动本身就是特征。
    #[test]
    fn settings_size_class_is_process_constant() {
        let baseline = h2_large_settings();
        for _ in 0..256 {
            assert_eq!(h2_large_settings(), baseline);
        }
        assert_eq!(
            h2_opening_size(FlowDirection::S2C, 0),
            Some(if baseline {
                SETTINGS_LARGE_WIRE
            } else {
                SETTINGS_SMALL_WIRE
            })
        );
    }
}
