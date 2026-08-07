//! Traffic script model and parser — the single canonical implementation.
//!
//! Both config validation (`shared::validate_traffic_script`) and the session
//! traffic shaper (`kanotls-session`) build on this parser, so the two can
//! never drift apart. The shaper applies its own per-connection randomization
//! pass on top of the parsed rules; that stays on the session side.

#[derive(Clone, Debug)]
pub enum DelaySpec {
    None,
    /// 记录间延迟的对数正态模型。
    ///
    /// **`mu_ms` 是对数空间的位置参数**（即 `ln(中位数毫秒)`），不是毫秒。
    /// 配置语法 `D:` 的两种写法都以**中位数毫秒**为输入，由 `parse_delay_spec`
    /// 统一取 `ln` 后存进这里；`sigma_ms` 同样是对数空间的形状参数（无量纲，
    /// 名字里的 `_ms` 是历史遗留）。
    ///
    /// 此前 `D:d`（单参数）存 `d.ln()`、`D:m-s`（双参数）把 `m` **原样**存进
    /// `mu_ms`，同一个数字在两种写法下语义相反：文档与 §3.5 示例都按「中位数
    /// 毫秒」描述，于是 `D:1.5-0.6` 的实际中位数是 `e^1.5` = 4.48ms（3.0×）、
    /// `D:3.0-0.7` 是 20.09ms（6.7×）、§3.5 声称 ~1.8ms 的 `D:2.0-0.5` 是
    /// 7.39ms（4.1×）。照文档写脚本会得到 3–7 倍长的记录间延迟——那是一份被
    /// 实质改写过的时序画像，而操作员完全无从察觉。现两种写法统一为中位数毫秒。
    LogNormal {
        mu_ms: f64,
        sigma_ms: f64,
    },
}

/// `D:` 的中位数上界（毫秒）。
///
/// 此前双参数形式对 `mu` 无任何上界校验，而 `mu` 又被当作对数空间的位置参数
/// 直接存下：`D:1000-0.5` ⇒ `exp(1000)` = `inf` ⇒ `(inf * 1000.0) as u64` 在
/// Rust 的浮点→整数 `as` 转换里**饱和**为 `u64::MAX` ⇒
/// `Duration::from_micros(u64::MAX)` ≈ 58.5 万年，连接在第一条带延迟的记录上
/// 永久挂死。现改为在**解析时**拒绝。
///
/// 上界取 500ms 的依据：脚本管辖的是外层握手刚结束后的头几条应用数据记录，
/// 真实 H2 在这个窗口里的记录间时距是亚毫秒到数十毫秒（同一 flight 内背靠背，
/// 跨请求的时距由 RTT 与服务端处理时间决定）。半秒已经是「用户点了一下」的
/// 量级，再大就不再是任何真实 H2 连接开场的形态。超界即解析失败并回退内嵌
/// 默认脚本，与既有错误处理口径一致。
pub const MAX_DELAY_MEDIAN_MS: f64 = 500.0;

/// `D:m-s` 的 sigma 上界。
///
/// 与中位数上界同源的挂死风险：单次采样是 `exp(mu + sigma·z)`，sigma 足够大时
/// 即使中位数合法，正态尾部也会把某一次采样推到数天量级（sigma = 5、z = 4 ⇒
/// 中位数 × e^20 ≈ ×4.9e8）。真实网络 IAT 拟合出的对数正态 sigma 落在 0.5–1.5，
/// 内嵌默认脚本用的是 0.5–0.7；2.0 已经把 99.9 分位放宽到中位数的约 480 倍。
pub const MAX_DELAY_SIGMA: f64 = 2.0;

/// `F:n?k` 抖动偏移的上界（记录数）。
///
/// 无界 `|k|` 会让 `shaper::TrafficShaper` 的 `deferred_fakes` 队列无界增长，
/// 且 `release_due_fakes` 每次策略调用都要为整个队列做一次全量扫描。64 条
/// 记录远超脚本实际管辖的观测窗口，超界即解析失败并回退内嵌默认脚本。
pub const MAX_FAKE_JITTER_OFFSET: i32 = 64;

#[derive(Clone, Debug)]
pub struct ScriptRule {
    pub len_lo: usize,
    pub len_hi: usize,
    /// `L:base?range` 标记：窗口在**每连接一次**的 `randomize_script` 里坍缩
    /// 成固定值，此前在 parse 期用 `thread_rng()` 抽样——校验（`shared.rs`）
    /// 与 shaper 构造各抽一次、取值不同，L1 lint 判据随运行而变。parse 现在
    /// 完全确定：`?` 规则存 `(base, base+range)` 窗口，lint 按窗口下界（保守
    /// 方向）判断。
    pub len_pinned: bool,
    pub delay: DelaySpec,
    pub expect_responses: u8,
    /// Fake-response position jitter: the emission offset (in records,
    /// relative to the triggering record) is sampled uniformly from
    /// `[min(0, k), max(0, k)]` each time the rule fires. `0` pins the fake
    /// to the current record; negative offsets emit before the current
    /// record, positive offsets defer to a later record.
    pub fake_jitter: i32,
}

#[derive(Clone, Debug)]
pub struct ParsedScript {
    pub rules: Vec<ScriptRule>,
    /// Total number of scripted records. Rules are cycled via
    /// `packet_seq % rules.len()` until `packet_seq` reaches `stop`.
    pub stop: u64,
}

/// Parse a traffic script given as an array of entries:
///
/// - `stop=N` — optional control entry, at most one; defaults to the rule
///   count. Must be >= 1.
/// - `i=L:lo-hi,D:d,F:f` — rule entry; the index `i` must be exactly the
///   0-based position of the rule (0, 1, 2, ...).
///
/// Whitespace around tokens is tolerated. Every entry must be non-empty and
/// well-formed; any error rejects the whole script (the caller falls back to
/// the embedded default script).
///
/// `L: base?range` semantics: the value is fixed for the lifetime of the
/// connection, sampled **per connection** as `base + U[0, range]` in the
/// shaper's `randomize_script` pass (the window collapses there). Parse
/// itself is deterministic — validation, lint and the runtime all agree on
/// the same window.
pub fn parse_traffic_script(lines: &[String]) -> Result<ParsedScript, String> {
    let mut rules = Vec::new();
    let mut stop: Option<u64> = None;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            return Err("empty script entry".to_string());
        }
        let (head, body) = line
            .split_once('=')
            .ok_or_else(|| format!("entry '{}' is missing '='", line))?;
        let head = head.trim();
        let body = body.trim();
        if head == "stop" {
            if stop.is_some() {
                return Err("duplicate stop entry".to_string());
            }
            let n: u64 = body
                .parse()
                .map_err(|e| format!("bad stop value '{}': {}", body, e))?;
            if n == 0 {
                return Err("stop must be >= 1".to_string());
            }
            stop = Some(n);
            continue;
        }
        let idx: usize = head
            .parse()
            .map_err(|e| format!("bad rule index '{}': {}", head, e))?;
        if idx != rules.len() {
            return Err(format!(
                "rule index {} out of order (expected {})",
                idx,
                rules.len()
            ));
        }
        rules.push(parse_rule_body(body)?);
    }
    if rules.is_empty() {
        return Err("script contains no rules".to_string());
    }
    let stop = stop.unwrap_or(rules.len() as u64);
    Ok(ParsedScript { rules, stop })
}

fn parse_rule_body(body: &str) -> Result<ScriptRule, String> {
    let mut len_range = None;
    let mut delay: DelaySpec = DelaySpec::None;
    let mut fake_response: u8 = 0;
    let mut fake_jitter: i32 = 0;

    for part in body.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("L:") {
            len_range = Some(parse_len_spec(rest.trim())?);
        } else if let Some(rest) = part.strip_prefix("D:") {
            delay = parse_delay_spec(rest.trim())?;
        } else if let Some(rest) = part.strip_prefix("F:") {
            let (count, jitter) = parse_fake_spec(rest.trim())?;
            fake_response = count;
            fake_jitter = jitter;
        } else {
            return Err(format!("unknown field '{}'", part));
        }
    }

    let (len_lo, len_hi, len_pinned) =
        len_range.ok_or_else(|| format!("missing L field in '{}'", body))?;
    Ok(ScriptRule {
        len_lo,
        len_hi,
        len_pinned,
        delay,
        expect_responses: fake_response,
        fake_jitter,
    })
}

fn parse_len_spec(rest: &str) -> Result<(usize, usize, bool), String> {
    if let Some((lo, hi)) = rest.split_once('-') {
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
        Ok((lo, hi, false))
    } else if let Some((base, range)) = rest.split_once('?') {
        // `?` 只标记窗口、**不抽样**：parse 保持确定性，坍缩发生在 shaper 的
        // `randomize_script`（每连接一次，见 `ScriptRule::len_pinned`）。此前在
        // 这里用 `thread_rng()` 抽固定值，导致校验与运行各取一个不同的值、
        // L1 lint 判据随运行而变。
        let base: usize = base
            .trim()
            .parse()
            .map_err(|e| format!("bad len base: {}", e))?;
        let range: usize = range
            .trim()
            .parse()
            .map_err(|e| format!("bad len range: {}", e))?;
        Ok((base, base.saturating_add(range), true))
    } else {
        // Bare `L: N` is a fixed value, lo == hi == N.
        let fixed: usize = rest
            .trim()
            .parse()
            .map_err(|e| format!("bad fixed len: {}", e))?;
        Ok((fixed, fixed, false))
    }
}

/// `D:` 两种写法共用的中位数 → 对数空间位置参数换算，含上界与有限性校验。
///
/// 有限性必须显式判：`"inf".parse::<f64>()` / `"nan".parse::<f64>()` 都成功，
/// 而 NaN 在 `<= 0.0` 与 `> MAX` 两个比较里都返回 false，只做区间比较会让它
/// 一路穿到 `Duration::from_micros`。
fn median_ms_to_mu(median_ms: f64) -> Result<f64, String> {
    if !median_ms.is_finite() || median_ms <= 0.0 {
        return Err(format!(
            "delay median '{}' must be a positive, finite number of milliseconds",
            median_ms
        ));
    }
    if median_ms > MAX_DELAY_MEDIAN_MS {
        return Err(format!(
            "delay median {}ms exceeds the {}ms limit",
            median_ms, MAX_DELAY_MEDIAN_MS
        ));
    }
    Ok(median_ms.ln())
}

/// `D:` 的两种写法：
///
/// * `D:0` / `D:0.0` —— 零延迟（`DelaySpec::None`）；
/// * `D:median` —— 中位数毫秒，sigma 取默认 0.5；
/// * `D:median-sigma` —— 中位数毫秒 + 对数空间 sigma。
///
/// **两种写法的第一个数字含义完全一致，都是中位数毫秒**（见 `DelaySpec` 的
/// 文档：此前双参数形式把它当对数空间的 mu 直接存下，同一个数字在两种写法下
/// 差出 3–7 倍）。
fn parse_delay_spec(rest: &str) -> Result<DelaySpec, String> {
    // 先按 f64 整体解析：任何 == 0.0 的写法（`0`、`0.0`、`0.00`…）都是零延迟。
    // 此前只识别字面量 `"0"`，`D:0.0` 会落到中位数校验里被拒绝。
    if rest.parse::<f64>().map(|v| v == 0.0).unwrap_or(false) {
        return Ok(DelaySpec::None);
    }
    if let Some((median_s, sigma_s)) = rest.split_once('-') {
        let median_ms: f64 = median_s
            .trim()
            .parse()
            .map_err(|e| format!("bad delay median: {}", e))?;
        let sigma: f64 = sigma_s
            .trim()
            .parse()
            .map_err(|e| format!("bad delay sigma: {}", e))?;
        if !sigma.is_finite() || sigma < 0.0 {
            return Err(format!("delay sigma '{}' must be finite and >= 0", sigma));
        }
        if sigma > MAX_DELAY_SIGMA {
            return Err(format!(
                "delay sigma {} exceeds the {} limit",
                sigma, MAX_DELAY_SIGMA
            ));
        }
        Ok(DelaySpec::LogNormal {
            mu_ms: median_ms_to_mu(median_ms)?,
            sigma_ms: sigma,
        })
    } else {
        let median_ms: f64 = rest.parse().map_err(|e| format!("bad delay: {}", e))?;
        Ok(DelaySpec::LogNormal {
            mu_ms: median_ms_to_mu(median_ms)?,
            sigma_ms: 0.5,
        })
    }
}

fn parse_fake_spec(rest: &str) -> Result<(u8, i32), String> {
    if let Some((count_s, jitter_s)) = rest.split_once('?') {
        let count: u8 = count_s
            .trim()
            .parse()
            .map_err(|e| format!("bad fake count: {}", e))?;
        let jitter: i32 = jitter_s
            .trim()
            .parse()
            .map_err(|e| format!("bad fake jitter: {}", e))?;
        if jitter.abs() > MAX_FAKE_JITTER_OFFSET {
            return Err(format!(
                "fake jitter {} exceeds the ±{} record bound",
                jitter, MAX_FAKE_JITTER_OFFSET
            ));
        }
        Ok((count, jitter))
    } else {
        let count: u8 = rest
            .trim()
            .parse()
            .map_err(|e| format!("bad fake: {}", e))?;
        Ok((count, 0))
    }
}

// ---------------------------------------------------------------------------
// 语义校验（lint）
// ---------------------------------------------------------------------------

/// 以下四个常量是 `crates/session/src/shaper.rs`（`SCRIPT_LEN_SCALE_LO/HI`）与
/// `crates/tunnel/src/{common.rs, control_size.rs}`（`MIN_DATA_WIRE_LEN`、
/// `L1_MAX_WIRE_LEN`、`MAX_DATA_RECORD_PAYLOAD`）的**镜像**。
///
/// config 是依赖图的叶子（tunnel / session 都依赖它，反向依赖会成环），因此
/// 这里只能复制而不能引用。改动那两侧时必须同步本处——
/// `lint_*` 与 `reference_script_*` 系列测试是这份耦合的哨兵。
const SHAPER_LEN_SCALE_LO: f64 = 0.85;
const SHAPER_LEN_SCALE_HI: f64 = 1.20;

/// 一条零载荷整形数据记录的线速开销：5(TLS 头) + 2(块长前缀) + 1(内层类型)
/// + 16(AEAD tag)。线速尺寸 = 载荷 + 该常量。
const DATA_RECORD_WIRE_OVERHEAD: usize = 24;

/// 论文（USENIX Security 2024, Xue et al.）离散化包尺寸时 `L1` 类的上界。
const L1_MAX_WIRE_LEN: usize = 160;

/// 单个 MTU 分段内可容纳的数据记录线速尺寸上界（载荷 1400 + 开销 24）。
const MAX_SINGLE_SEGMENT_WIRE_LEN: usize = 1400 + DATA_RECORD_WIRE_OVERHEAD;

/// `stop` 相对规则数的循环次数上界（`stop <= 1.5 × 规则数`），以整数比表达。
const MAX_SCRIPT_CYCLES_NUM: u64 = 3;
const MAX_SCRIPT_CYCLES_DEN: u64 = 2;

/// 一条规则经逐连接随机化后可能取到的**最小**线速尺寸。
///
/// `randomize_script` 对 `len_lo` 乘 U[0.85, 1.20] 后用 `as usize` 截断（对正数
/// 即向下取整）再 `.max(1)`，`script_policy` 又从 `[len_lo, len_hi]` 均匀采样，
/// 因此最小可达载荷就是 `max(1, floor(len_lo × 0.85))`。
fn min_randomized_wire_len(len_lo: usize) -> usize {
    ((len_lo as f64 * SHAPER_LEN_SCALE_LO) as usize).max(1) + DATA_RECORD_WIRE_OVERHEAD
}

/// 一条规则经逐连接随机化后可能取到的**最大**线速尺寸。
fn max_randomized_wire_len(len_hi: usize) -> usize {
    (len_hi as f64 * SHAPER_LEN_SCALE_HI) as usize + DATA_RECORD_WIRE_OVERHEAD
}

/// 对一份**已解析成功**的脚本做语义校验，返回人类可读的警告列表（空 = 无问题）。
///
/// 此前 `shared::validate_traffic_script` 只检查「能否解析」，于是一份语法完全
/// 合法、但会主动制造论文判别特征的脚本可以静默上线。这里检查的四项都不是
/// 语法问题，而是**会在观测窗口里产生可判别结构**的取值组合。
///
/// 全部为警告而非解析失败，理由是回退语义：解析失败 ⇒ 回退内嵌默认脚本 ⇒
/// 这个部署重新掉回「全世界跑同一份默认」的群体里，而那正是自定义脚本存在的
/// 唯一理由。把操作员的意图静默替换成群体默认，比让他带着一条警告跑自己的
/// 分布更糟。
pub fn lint_traffic_script(script: &ParsedScript) -> Vec<String> {
    let mut warnings = Vec::new();

    for (idx, rule) in script.rules.iter().enumerate() {
        // 1) F:m > 0 —— 在连接开场注入 PING/PING-ACK 对。
        //
        // `F:n` 会在触发记录处插入一条 `CMD_PADDING` 请求，其线速尺寸恒为
        // H2 PING 的 41 字节，对端回一条 41 字节的 PING-ACK。真实 H2 的 PING
        // 是 30–150 秒量级的保活帧，不会出现在连接开场的头几百毫秒里；更糟的是
        // 「小的本端包 → 小的对端包」若紧跟一个下行 burst，就构成论文判别力
        // 第 3 的 3-gram `(−L4, L1, −L1)`（Distinc 2.879）。内嵌默认脚本已把全部
        // `expect_responses` 置 0。用户脚本仍可使用（不静默忽略），但必须警告。
        if rule.expect_responses > 0 {
            warnings.push(format!(
                "rule {} sets F:{} — every trigger injects a 41-byte PING-sized CMD_PADDING \
                 request and a PING-sized reply. Real HTTP/2 PINGs are 30-150s keepalives, not \
                 opening-flight frames; a small local packet answered by a small peer packet right \
                 after a downstream burst reproduces the (-L4, L1, -L1) 3-gram. Prefer F:0.",
                idx, rule.expect_responses
            ));
        }

        // 2) 随机化后的长度可能落进论文的 L1 类（线速 ≤ 160 字节）。
        //
        // 判据是 `floor(len_lo × 0.85) + 24 <= 160`，等价于 `len_lo <= 161`
        // ——注意是 161 而不是 160：161 × 0.85 = 136.85 ⇒ 截断 136 ⇒ 线速恰好
        // 160，仍在 L1 内；162 才是第一个安全值（137 + 24 = 161）。
        //
        // 一条 L1 类的**本端**数据记录紧跟对端大 burst，就精确复现论文判别力
        // 第 1 的 3-gram `(L2, −L4, L1)`（Distinc 7.226）。交互采样路径的数据
        // 记录有硬编码下界 `MIN_DATA_RECORD_PAYLOAD` 挡着，**脚本路径没有**：
        // `script_policy` 直接 `gen_range(len_lo..=len_hi)`，不做任何 L1 钳制。
        let min_wire = min_randomized_wire_len(rule.len_lo);
        if min_wire <= L1_MAX_WIRE_LEN {
            warnings.push(format!(
                "rule {} has len_lo={} — after the per-connection U[{}, {}] scaling its records can \
                 be as small as {} bytes on the wire, which falls into the paper's L1 size class \
                 (<= {}). An L1 local record right after a large peer burst reproduces the highest \
                 ranked 3-gram (L2, -L4, L1). Use len_lo >= 162 (>= 200 for margin).",
                idx,
                rule.len_lo,
                SHAPER_LEN_SCALE_LO,
                SHAPER_LEN_SCALE_HI,
                min_wire,
                L1_MAX_WIRE_LEN
            ));
        }

        // 3) 随机化后的长度可能超出单个 MTU 分段。
        //
        // 一条记录跨多个 TCP 段，与「一条 H2 帧一个段」的形态不符：论文观测的
        // 单位是 TCP 载荷字节数，一条 1700 字节的记录在线上是「一个满段 +
        // 一个小尾段」，那个小尾段本身可能落进 L1/L2。提示性警告即可——bulk
        // 态本来就发满载记录，大记录不是绝对错误。
        let max_wire = max_randomized_wire_len(rule.len_hi);
        if max_wire > MAX_SINGLE_SEGMENT_WIRE_LEN {
            warnings.push(format!(
                "rule {} has len_hi={} — after the per-connection U[{}, {}] scaling its records can \
                 reach {} bytes on the wire, past the {}-byte single-MTU-segment budget. Such a \
                 record is split across TCP segments, so the classifier sees one full segment plus \
                 a small tail segment instead of one H2-frame-shaped packet. Use len_hi <= 1166.",
                idx,
                rule.len_hi,
                SHAPER_LEN_SCALE_LO,
                SHAPER_LEN_SCALE_HI,
                max_wire,
                MAX_SINGLE_SEGMENT_WIRE_LEN
            ));
        }
    }

    // 4) stop 远大于规则数 ⇒ 观测窗口内的周期性自相关。
    //
    // 规则按 `packet_seq % rules.len()` 循环，因此 `stop / rules.len()` 就是脚本
    // 在观测窗口里重复的周期数。跑满 4 个周期意味着尺寸序列带一个周期恰为
    // `rules.len()` 的自相关峰——真实 H2 的记录尺寸序列没有这种结构，这个峰
    // 本身就是一条判别特征（而且它是**脚本独有**的，恰好把「自定义脚本用于
    // 去聚类」的收益反转成一条新的、这个部署独有的特征）。
    //
    // 单规则脚本不判：`rules.len() == 1` 时不存在「周期」，所有记录本来就来自
    // 同一个分布，没有可供相关的相位。
    let rule_count = script.rules.len() as u64;
    // saturating_mul：`stop` 接近 u64::MAX 时普通乘法在 debug 构建下直接 panic
    // （一个本应只产生警告的输入路径），饱和后判据照常给出「远超 1.5 倍」。
    if rule_count >= 2
        && script.stop.saturating_mul(MAX_SCRIPT_CYCLES_DEN)
            > rule_count.saturating_mul(MAX_SCRIPT_CYCLES_NUM)
    {
        warnings.push(format!(
            "stop={} over {} rules means the script replays its rule cycle {:.1} times. Rules are \
             applied as packet_seq % rule_count, so repeating the cycle injects a periodic \
             autocorrelation (period = rule count) into the record-size sequence inside the \
             paper's Wo = 25 observation window — a feature real HTTP/2 does not have. Keep stop \
             at most 1.5x the rule count, or add more distinct rules.",
            script.stop,
            rule_count,
            script.stop as f64 / rule_count as f64
        ));
    }

    warnings
}

// ---------------------------------------------------------------------------
// 参考脚本
// ---------------------------------------------------------------------------

/// 参考流量脚本——**模板，不是标准答案**。
///
/// # 1. 这份脚本改善什么、不改善什么
///
/// 论文（USENIX Security 2024, Xue et al., *Fingerprinting Obfuscated Proxy
/// Traffic with Encapsulated TLS Handshakes*）的判别量是：外层握手之后
/// `Wo = 25` 个承载数据的 TCP 包，序列为**带方向的 TCP 载荷字节数**；离散成
/// `L1: 1–160 / L2: 161–600 / L3: 601–1210 / L4: 1211+` 四类后取 n-gram；burst
/// 为「方向相同的连续包尺寸累加，由方向改变**或** ≥3×RTT 间隔打断」；粗筛规则是
/// `往返次数 < 2.5 AND 首个 burst < 300 字节`。
///
/// **这些判别量基本都不由脚本控制**：
///
/// * 第一个上行 burst 的尺寸与「立刻让出方向」由 `shaper.rs` 的
///   `FIRST_RECORD_PAYLOAD_LO/HI`（152–248 载荷 ⇒ 176–272 线速）+ `quiet_gap`
///   硬编码保证，**抢在脚本之前**（客户端方向的 `packet_seq == 0` 根本不查脚本）；
/// * 往返次数由对端按真实 H2 语义回的 `SETTINGS / WINDOW_UPDATE / SETTINGS-ACK`
///   开场 flight、以及合成 H2 请求/响应交换提供，脚本里没有任何字段能表达它；
/// * TCP 分段边界由 `drive_shaper` 的批量 flush 决定（连续 `D:0` 的记录会被攒进
///   同一次 `write()`，最多 8 条一批）——脚本能影响它的**唯一**手段是 `D:` 非零
///   （非零延迟强制先 flush 再 sleep），而这是个副作用，不是可以精确编排的旋钮；
/// * `stop` 之后的记录交给确定性两态稳态（bulk 闩锁 / 交互采样），尺寸来自
///   `control_size.rs` 里硬编码的截断正态或满载记录，脚本管不到。
///
/// 结论：在 25 包的观测窗口里，脚本实际只管辖头几条**本端数据记录**的尺寸与
/// 记录间时距。**脚本写错只会更差，写对也不会更好。**
///
/// 那它的价值是什么？**跨部署的群体去聚类。** 如果全世界的部署都跑同一份内嵌
/// 默认，那份默认的尺寸/IAT 分布本身就成了一个可拟合的**群体特征**：审查方拟合
/// 一次即命中全部默认部署。自定义脚本让一个部署把自己的分布移开。
///
/// # 2. 照抄这份脚本会重建群体特征
///
/// 这是一把双刃剑：脚本只有在你选的分布**同样是某个真实应用的分布**时才有帮助。
/// 选一个不像任何真实应用的分布，只会让这个部署**单独**变得可识别——从「混在
/// KanoTLS 群体里」变成「一个独一无二的怪异分布」。
///
/// 由此推出一条硬性结论：**如果所有人照抄下面这份 `REFERENCE_TRAFFIC_SCRIPT`，
/// 它立刻变成新的群体特征**，和内嵌默认没有任何区别。它存在的意义是给出一组
/// 满足全部安全约束的**示例取值**，让你看清约束长什么样，然后**用第 3 节的方法
/// 推导你自己的**。
///
/// # 3. 如何推导你自己的脚本（可照做）
///
/// 目标：让脚本的尺寸/时距分布等于**你想模仿的那个真实应用**在外层 TLS 握手
/// 之后头几条应用数据记录的经验分布。选目标时要选一个「你的出口 IP 访问它很
/// 自然」的站点——某个 CDN 站点、某个 API 端点、某类网页浏览。
///
/// 1. **抓包**（在客户端所在网络，用真实浏览器/客户端访问目标）：
///    ```text
///    tshark -i <网卡> -f "tcp port 443 and host <目标域名>" -w ref.pcap
///    ```
/// 2. **定位窗口起点**：外层握手结束的位置就是第一条 `application_data`
///    （TLS 记录 content_type = 23）。
/// 3. **导出本方向的记录尺寸与时间**（`<你的IP>` 换成客户端地址；服务端侧脚本
///    则反过来取 `ip.dst`）：
///    ```text
///    tshark -r ref.pcap -Y "tls.record.content_type==23 && ip.src==<你的IP>" \
///           -T fields -e frame.time_relative -e tls.record.length
///    ```
///    取这条序列的**前 25–30 条**——再往后就出了论文的观测窗口，没有意义。
/// 4. **换算成 `L:`**：`tls.record.length` 是 TLS 记录体长度，线速尺寸 =
///    `length + 5`，KanoTLS 的脚本 `L:` 填的是**载荷**，即
///    `载荷 = length + 5 − 24 = length − 19`。对每一段取经验分位数，用
///    `p10-p90` 作为一条规则的 `L:lo-hi`（不要用 min-max：极值会把区间拉得
///    比真实分布宽，采样出真实应用不会产生的尺寸）。
/// 5. **换算成 `D:`**：对相邻记录的 `frame.time_relative` 求差得到 IAT 序列
///    （毫秒）。`D:` 的第一个数字填这段 IAT 的**中位数（毫秒）**，第二个数字填
///    `stddev(ln(IAT_ms))`（对数空间的标准差，典型 0.5–1.0）。抓到的相邻记录
///    若几乎同时到达（同一个 TCP 段里的多条记录），那一条就写 `D:0`。
/// 6. **分段成规则**：把这 25–30 条记录按「形状明显变化」切成 4–6 段，每段出
///    一条规则，`stop` 取实际观测到的记录条数（且不超过规则数的 1.5 倍，见下）。
/// 7. **过校验**：把结果写进配置启动一次，确认没有任何
///    `traffic_script` 警告（见 `lint_traffic_script`）。有警告说明你抓到的
///    分布触到了某条会制造判别特征的边界，需要按警告文字调整。
///
/// # 4. 每条规则必须满足的硬约束（由 `lint_traffic_script` 检查）
///
/// * `len_lo >= 162`（安全值取 >= 200）——`randomize_script` 会乘 U[0.85, 1.20]，
///   线速 = 载荷 + 24，`len_lo = 161` 的最小线速恰好 160，仍在 `L1` 类内；
/// * `len_hi <= 1166`——×1.20 后载荷 ≤ 1400，整条记录仍装进一个 MTU 分段；
/// * `F:0`——不在连接开场注入 PING/PING-ACK 对；
/// * `D:` 的第一个数字是**中位数毫秒**（两种写法一致），落在真实网络 IAT 量级；
/// * `stop <= 1.5 × 规则数`——避免在观测窗口里注入周期性自相关。
///
/// # 5. 下面这组取值的来历
///
/// 尺寸区间取自真实 H2 的 `HEADERS` 帧与小 `DATA` 帧量级，与 codebase 里已有的
/// 两组经验分布同量级：`control_size.rs` 的 HEADERS 截断正态（C2S μ450/σ120
/// 截断 [250, 800]、S2C μ200/σ50 截断 [100, 400]）、以及非 bulk 数据记录分布
/// （C2S μ450/σ250、S2C μ700/σ400，截断 [137, 1400]）。时距取「同一 flight 内
/// 背靠背 ⇒ `D:0`；跨请求 ⇒ 数毫秒中位数」的形态。
///
/// 注意脚本是**方向无关**的：客户端与服务端各自读自己配置里的
/// `session.traffic_script`，同一份脚本在哪一侧就按哪一侧的方向跑。上面的
/// C2S/S2C 非对称性因此只能靠两侧分别配置来表达——这是脚本模型的又一条
/// 表达力上限。
pub const REFERENCE_TRAFFIC_SCRIPT: &[&str] = &[
    "stop=6",
    // 首条请求头量级；与前一条记录背靠背（同一 flight）。
    "0=L:260-520,D:0,F:0",
    // 短随附帧（continuation / 小 DATA），跨一个 RTT 量级的间隔。
    "1=L:210-330,D:2.5-0.6,F:0",
    // 响应头 + 首个 DATA 帧量级；与上一条同批出网。
    "2=L:340-700,D:0,F:0",
    // 第二个请求：浏览器在开场窗口内继续发请求的形态。
    "3=L:280-460,D:4.0-0.55,F:0",
    // 稍大的 DATA 帧，仍在单个 MTU 分段内。
    "4=L:420-900,D:1.8-0.7,F:0",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_single_rule() {
        let p = parse_traffic_script(&lines(&["0=L:200-250,D:0,F:0"])).unwrap();
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.stop, 1);
        assert_eq!(p.rules[0].len_lo, 200);
        assert_eq!(p.rules[0].len_hi, 250);
        assert_eq!(p.rules[0].expect_responses, 0);
        assert_eq!(p.rules[0].fake_jitter, 0);
    }

    fn median_ms(delay: &DelaySpec) -> f64 {
        match delay {
            DelaySpec::LogNormal { mu_ms, .. } => mu_ms.exp(),
            DelaySpec::None => 0.0,
        }
    }

    /// `D:m-s` 的 `m` 是**中位数毫秒**，与单参数 `D:d` 完全一致。此前它被
    /// 原样存进 `mu_ms`（对数空间位置参数），于是 `D:10-0.5` 的实际中位数是
    /// `e^10` ≈ 22026ms 而不是 10ms。
    #[test]
    fn parse_with_delay_and_fake() {
        let p = parse_traffic_script(&lines(&["0=L:100-200,D:10-0.5,F:3"])).unwrap();
        assert_eq!(p.rules[0].expect_responses, 3);
        match p.rules[0].delay {
            DelaySpec::LogNormal { mu_ms, sigma_ms } => {
                assert!((mu_ms - 10.0_f64.ln()).abs() < 1e-9);
                assert!((sigma_ms - 0.5).abs() < 0.01);
            }
            _ => panic!("expected LogNormal"),
        }
        assert!((median_ms(&p.rules[0].delay) - 10.0).abs() < 1e-9);
    }

    /// 核心回归：`D:d` 与 `D:d-s` 对同一个数字必须给出同一个中位数。
    #[test]
    fn delay_single_and_two_parameter_forms_agree_on_the_median() {
        for median in ["1.5", "2.0", "3.0", "0.4", "120"] {
            let one = parse_traffic_script(&lines(&[&format!("0=L:300,D:{}", median)])).unwrap();
            let two =
                parse_traffic_script(&lines(&[&format!("0=L:300,D:{}-0.5", median)])).unwrap();
            let expected: f64 = median.parse().unwrap();
            assert!(
                (median_ms(&one.rules[0].delay) - expected).abs() < 1e-9,
                "D:{} single-parameter median drifted",
                median
            );
            assert!(
                (median_ms(&two.rules[0].delay) - expected).abs() < 1e-9,
                "D:{} two-parameter median drifted",
                median
            );
        }
    }

    /// 文档（§3.5）与内嵌默认脚本用的那三组取值，解析后必须真的是
    /// 1.5 / 2.0 / 3.0 毫秒——此前分别是 4.48 / 7.39 / 20.09ms（3.0× / 4.1× /
    /// 6.7×），照文档写脚本会得到一份被实质改写过的时序画像。
    #[test]
    fn documented_delay_values_now_match_their_stated_medians() {
        for (spec, expected) in [("1.5-0.6", 1.5), ("2.0-0.5", 2.0), ("3.0-0.7", 3.0)] {
            let p = parse_traffic_script(&lines(&[&format!("0=L:300,D:{}", spec)])).unwrap();
            assert!(
                (median_ms(&p.rules[0].delay) - expected).abs() < 1e-9,
                "D:{} median is {} not {}",
                spec,
                median_ms(&p.rules[0].delay),
                expected
            );
        }
    }

    /// 任务 1b：中位数上界。`D:1000-0.5` 此前 ⇒ `exp(1000)` = inf ⇒
    /// `(inf * 1000.0) as u64` 饱和为 `u64::MAX` ⇒ `Duration::from_micros`
    /// ≈ 58.5 万年，连接在第一条带延迟的记录上永久挂死。
    #[test]
    fn parse_rejects_delays_that_would_hang_the_connection() {
        for spec in ["D:1000-0.5", "D:1000", "D:501", "D:500.1-0.5", "D:1e9-0.5"] {
            assert!(
                parse_traffic_script(&lines(&[&format!("0=L:300,{}", spec)])).is_err(),
                "{} must be rejected",
                spec
            );
        }
        // 上界本身合法。
        let p = parse_traffic_script(&lines(&["0=L:300,D:500-0.5"])).unwrap();
        assert!((median_ms(&p.rules[0].delay) - 500.0).abs() < 1e-9);
    }

    /// 非有限值必须显式拒绝：NaN 在 `<= 0.0` 与 `> MAX` 两个比较里都是 false，
    /// 只做区间比较会让它一路穿到 `Duration::from_micros`。
    #[test]
    fn parse_rejects_non_finite_delays() {
        for spec in [
            "D:inf",
            "D:inf-0.5",
            "D:NaN",
            "D:NaN-0.5",
            "D:2.0-inf",
            "D:2.0-NaN",
        ] {
            assert!(
                parse_traffic_script(&lines(&[&format!("0=L:300,{}", spec)])).is_err(),
                "{} must be rejected",
                spec
            );
        }
    }

    /// sigma 上界：采样值是 `exp(mu + sigma·z)`，sigma 足够大时即使中位数合法，
    /// 正态尾部也会把单次采样推到数天量级。
    #[test]
    fn parse_rejects_oversized_delay_sigma() {
        assert!(parse_traffic_script(&lines(&["0=L:300,D:2.0-5.0"])).is_err());
        assert!(parse_traffic_script(&lines(&["0=L:300,D:2.0-2.01"])).is_err());
        assert!(parse_traffic_script(&lines(&["0=L:300,D:2.0-2.0"])).is_ok());
    }

    #[test]
    fn parse_multiple_rules_with_stop() {
        let p = parse_traffic_script(&lines(&[
            "stop=7",
            "0=L:200-250,D:0,F:0",
            "1=L:300-400,D:5-0.5,F:1",
        ]))
        .unwrap();
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.stop, 7);
        assert_eq!(p.rules[1].len_lo, 300);
        assert_eq!(p.rules[1].expect_responses, 1);
    }

    #[test]
    fn parse_tolerates_whitespace() {
        let p =
            parse_traffic_script(&lines(&[" stop = 3 ", " 0 = L:150-300, D: 0, F:1 ?2 "])).unwrap();
        assert_eq!(p.stop, 3);
        assert_eq!(p.rules[0].len_lo, 150);
        assert_eq!(p.rules[0].len_hi, 300);
        assert_eq!(p.rules[0].expect_responses, 1);
        assert_eq!(p.rules[0].fake_jitter, 2);
    }

    #[test]
    fn parse_negative_fake_jitter() {
        let p = parse_traffic_script(&lines(&["0=L:100,D:0,F:1?-1"])).unwrap();
        assert_eq!(p.rules[0].expect_responses, 1);
        assert_eq!(p.rules[0].fake_jitter, -1);
    }

    /// 抖动偏移必须落在 ±MAX_FAKE_JITTER_OFFSET 内：无界 `|k|` 会让 shaper 的
    /// `deferred_fakes` 队列无界增长（`release_due_fakes` 每次策略调用全量扫描）。
    #[test]
    fn parse_rejects_out_of_bounds_fake_jitter() {
        for spec in ["F:1?65", "F:1?-65", "F:2?999", "F:2?-1000"] {
            assert!(
                parse_traffic_script(&lines(&[&format!("0=L:100,D:0,{}", spec)])).is_err(),
                "{} must be rejected",
                spec
            );
        }
        // 上界本身合法，正负两侧都放行。
        for spec in ["F:1?64", "F:1?-64"] {
            let p = parse_traffic_script(&lines(&[&format!("0=L:100,D:0,{}", spec)])).unwrap();
            assert_eq!(p.rules[0].fake_jitter.abs(), 64);
        }
    }

    #[test]
    fn parse_rejects_empty_entry() {
        assert!(parse_traffic_script(&lines(&[""])).is_err());
        assert!(parse_traffic_script(&lines(&["   "])).is_err());
        assert!(parse_traffic_script(&lines(&["0=L:100", ""])).is_err());
    }

    #[test]
    fn parse_rejects_missing_equals() {
        assert!(parse_traffic_script(&lines(&["L:100"])).is_err());
    }

    #[test]
    fn parse_rejects_out_of_order_index() {
        assert!(parse_traffic_script(&lines(&["1=L:100,D:0,F:0"])).is_err());
        assert!(parse_traffic_script(&lines(&["0=L:100", "0=L:200"])).is_err());
        assert!(parse_traffic_script(&lines(&["0=L:100", "2=L:200"])).is_err());
    }

    #[test]
    fn parse_rejects_duplicate_or_bad_stop() {
        assert!(parse_traffic_script(&lines(&["stop=1", "stop=2", "0=L:100"])).is_err());
        assert!(parse_traffic_script(&lines(&["stop=0", "0=L:100"])).is_err());
        assert!(parse_traffic_script(&lines(&["stop=x", "0=L:100"])).is_err());
    }

    #[test]
    fn parse_rejects_no_rules() {
        assert!(parse_traffic_script(&lines(&["stop=3"])).is_err());
        assert!(parse_traffic_script(&[]).is_err());
    }

    #[test]
    fn parse_rejects_unknown_field() {
        assert!(parse_traffic_script(&lines(&["0=L:100,X:1"])).is_err());
    }

    #[test]
    fn parse_rejects_inverted_range() {
        assert!(parse_traffic_script(&lines(&["0=L:250-200,D:0,F:0"])).is_err());
    }

    #[test]
    fn parse_rejects_missing_length() {
        assert!(parse_traffic_script(&lines(&["0=D:0,F:0"])).is_err());
    }

    #[test]
    fn parse_rejects_bad_delay() {
        assert!(parse_traffic_script(&lines(&["0=L:100,D:-1"])).is_err());
        assert!(parse_traffic_script(&lines(&["0=L:100,D:1--0.5"])).is_err());
        assert!(parse_traffic_script(&lines(&["0=L:100,D:1-(-0.5)"])).is_err());
    }

    #[test]
    fn parse_question_mark_syntax_marks_window_and_is_deterministic() {
        // `?` 只标记窗口、不抽样：parse 多次结果必须逐字节一致（此前在 parse
        // 期抽固定值，同一脚本每次解析结果都不同）。
        let mut expected: Option<ParsedScript> = None;
        for _ in 0..20 {
            let p = parse_traffic_script(&lines(&["0=L:100?50,D:0,F:0"])).unwrap();
            assert_eq!(p.rules.len(), 1);
            let rule = &p.rules[0];
            assert!(rule.len_pinned, "? 规则必须标记 len_pinned");
            assert_eq!(rule.len_lo, 100);
            assert_eq!(rule.len_hi, 150);
            if let Some(prev) = &expected {
                assert!(
                    prev.rules[0].len_lo == rule.len_lo && prev.rules[0].len_hi == rule.len_hi,
                    "parse 必须是确定性的：? 规则的窗口不得随解析而变"
                );
            }
            expected = Some(p);
        }
    }

    #[test]
    fn parse_range_and_bare_lengths_are_not_pinned() {
        for spec in ["0=L:100-200,D:0,F:0", "0=L:333,D:0,F:0"] {
            let p = parse_traffic_script(&lines(&[spec])).unwrap();
            assert!(!p.rules[0].len_pinned, "{} 不得标记 len_pinned", spec);
        }
    }

    #[test]
    fn parse_bare_number_fixed_value() {
        let p = parse_traffic_script(&lines(&["0=L:333,D:0,F:0"])).unwrap();
        assert_eq!(p.rules[0].len_lo, 333);
        assert_eq!(p.rules[0].len_hi, 333);
    }

    #[test]
    fn parse_bare_delay_is_lognormal_shorthand() {
        let p = parse_traffic_script(&lines(&["0=L:100,D:200"])).unwrap();
        match p.rules[0].delay {
            DelaySpec::LogNormal { mu_ms, sigma_ms } => {
                assert!((mu_ms - 200.0_f64.ln()).abs() < 0.01);
                assert!((sigma_ms - 0.5).abs() < 0.01);
            }
            _ => panic!("expected LogNormal"),
        }
    }

    /// 零延迟的三种写法必须解析成同一个 `DelaySpec::None`——此前只有字面量
    /// `"0"` 被识别，`D:0.0` 会被中位数校验拒绝。
    #[test]
    fn parse_zero_delay_accepts_decimal_zero() {
        for spec in ["D:0", "D:0.0", "D:0.00"] {
            let p = parse_traffic_script(&lines(&[&format!("0=L:300,{}", spec)])).unwrap();
            assert!(
                matches!(p.rules[0].delay, DelaySpec::None),
                "{} 必须解析成 DelaySpec::None",
                spec
            );
        }
    }

    #[test]
    fn parse_accepts_zero_range_lo() {
        // Unified semantics: a zero lower bound is accepted here and clamped
        // to >= 1 by the session-side randomization pass.
        let p = parse_traffic_script(&lines(&["0=L:0-100,D:0,F:0"])).unwrap();
        assert_eq!(p.rules[0].len_lo, 0);
        assert_eq!(p.rules[0].len_hi, 100);
    }

    // -----------------------------------------------------------------
    // 语义校验
    // -----------------------------------------------------------------

    fn lint(entries: &[&str]) -> Vec<String> {
        lint_traffic_script(&parse_traffic_script(&lines(entries)).unwrap())
    }

    fn lint_hits(entries: &[&str], needle: &str) -> bool {
        lint(entries).iter().any(|w| w.contains(needle))
    }

    #[test]
    fn lint_flags_fake_response_injection() {
        assert!(lint_hits(&["0=L:300-400,D:0,F:1"], "F:1"));
        assert!(lint_hits(&["0=L:300-400,D:0,F:2?-1"], "PING"));
        assert!(!lint_hits(&["0=L:300-400,D:0,F:0"], "PING"));
    }

    /// L1 判据的边界必须是 `len_lo <= 161`，不是 160：
    /// `161 × 0.85 = 136.85` ⇒ 截断 136 ⇒ 线速 `136 + 24 = 160`，恰好仍在
    /// `L1`（上界 160，闭区间）。162 才是第一个安全值。
    #[test]
    fn lint_l1_boundary_is_exactly_161() {
        assert_eq!(min_randomized_wire_len(161), 160);
        assert_eq!(min_randomized_wire_len(162), 161);
        for lo in [1usize, 100, 160, 161] {
            assert!(
                lint_hits(&[&format!("0=L:{}-900,D:0,F:0", lo)], "L1 size class"),
                "len_lo={} must be flagged",
                lo
            );
        }
        for lo in [162usize, 200, 400] {
            assert!(
                !lint_hits(&[&format!("0=L:{}-900,D:0,F:0", lo)], "L1 size class"),
                "len_lo={} must not be flagged",
                lo
            );
        }
    }

    /// MTU 判据：`len_hi × 1.20 + 24 > 1424` ⟺ `len_hi > 1166`。
    #[test]
    fn lint_mtu_boundary_is_exactly_1166() {
        assert_eq!(max_randomized_wire_len(1166), 1423);
        assert_eq!(max_randomized_wire_len(1167), 1424);
        assert!(!lint_hits(&["0=L:300-1166,D:0,F:0"], "single-MTU-segment"));
        assert!(!lint_hits(&["0=L:300-1167,D:0,F:0"], "single-MTU-segment"));
        assert!(lint_hits(&["0=L:300-1168,D:0,F:0"], "single-MTU-segment"));
        assert!(lint_hits(&["0=L:300-4000,D:0,F:0"], "single-MTU-segment"));
    }

    /// `stop` 远大于规则数 ⇒ 周期性自相关。单规则脚本不判（没有相位可言）。
    #[test]
    fn lint_flags_excessive_stop_cycles() {
        let six = [
            "0=L:300-400,D:0,F:0",
            "1=L:300-400,D:0,F:0",
            "2=L:300-400,D:0,F:0",
            "3=L:300-400,D:0,F:0",
            "4=L:300-400,D:0,F:0",
            "5=L:300-400,D:0,F:0",
        ];
        let with_stop = |n: u64| {
            let mut v = vec![format!("stop={}", n)];
            v.extend(six.iter().map(|s| s.to_string()));
            lint_traffic_script(&parse_traffic_script(&v).unwrap())
                .iter()
                .any(|w| w.contains("rule cycle"))
        };
        // 6 条规则：stop <= 9 放行，>= 10 告警（1.5 个周期）。
        assert!(!with_stop(6));
        assert!(!with_stop(9));
        assert!(with_stop(10));
        assert!(with_stop(26));

        // 单规则脚本不判。
        assert!(!lint_hits(
            &["stop=64", "0=L:300-400,D:0,F:0"],
            "rule cycle"
        ));
    }

    /// `stop = u64::MAX` 时 lint 必须返回警告而不是在乘法上 panic（debug 构建
    /// 下普通乘法会溢出回绕）。
    #[test]
    fn lint_survives_extreme_stop_without_panicking() {
        let p = parse_traffic_script(&lines(&[
            "stop=18446744073709551615",
            "0=L:300-400,D:0,F:0",
            "1=L:300-400,D:0,F:0",
        ]))
        .unwrap();
        assert_eq!(p.stop, u64::MAX);
        let warnings = lint_traffic_script(&p);
        assert!(
            warnings.iter().any(|w| w.contains("rule cycle")),
            "stop=u64::MAX 必须产生周期警告而非 panic"
        );
    }

    #[test]
    fn lint_accepts_a_clean_script() {
        assert!(lint(&["stop=3", "0=L:300-500,D:0,F:0", "1=L:220-380,D:2.0-0.6,F:0",]).is_empty());
    }

    /// 内嵌默认脚本（`shaper.rs::embedded_script` 的配置语法等价物）本身必须
    /// 是零警告的——否则「回退内嵌默认」这条错误处理路径会把部署推进一个
    /// 带判别特征的配置。
    #[test]
    fn embedded_default_script_is_lint_clean() {
        assert!(lint(&[
            "stop=6",
            "0=L:200-250,D:0,F:0",
            "1=L:180-220,D:1.5-0.6,F:0",
            "2=L:250-350,D:0,F:0",
            "3=L:300-400,D:2.0-0.5,F:0",
            "4=L:200-300,D:0,F:0",
            "5=L:400-600,D:3.0-0.7,F:0",
        ])
        .is_empty());
    }

    // -----------------------------------------------------------------
    // 参考脚本
    // -----------------------------------------------------------------

    #[test]
    fn reference_script_parses_and_is_lint_clean() {
        let parsed = parse_traffic_script(&lines(REFERENCE_TRAFFIC_SCRIPT))
            .expect("reference script must parse");
        let warnings = lint_traffic_script(&parsed);
        assert!(
            warnings.is_empty(),
            "reference script must produce zero warnings, got {:?}",
            warnings
        );
    }

    /// 参考脚本的每条规则都必须满足文档里写死的那组硬约束。这不是重复
    /// `lint_traffic_script`：那边是「不越界」，这边额外要求参考脚本留有余量
    /// （`len_lo >= 200` 而不是勉强的 162），以及分布落在真实 H2 HEADERS /
    /// 小 DATA 帧量级。
    #[test]
    fn reference_script_rules_satisfy_the_documented_constraints() {
        let parsed = parse_traffic_script(&lines(REFERENCE_TRAFFIC_SCRIPT)).unwrap();
        assert!(!parsed.rules.is_empty());
        for (idx, rule) in parsed.rules.iter().enumerate() {
            assert!(
                rule.len_lo >= 200,
                "rule {}: len_lo {} 未留出 L1 余量（硬下界 162）",
                idx,
                rule.len_lo
            );
            assert!(
                min_randomized_wire_len(rule.len_lo) > L1_MAX_WIRE_LEN,
                "rule {}: 随机化后可能落进 L1",
                idx
            );
            assert!(
                max_randomized_wire_len(rule.len_hi) <= MAX_SINGLE_SEGMENT_WIRE_LEN,
                "rule {}: 随机化后越出单个 MTU 分段",
                idx
            );
            assert!(rule.len_lo <= rule.len_hi);
            // 真实 H2 HEADERS / 小 DATA 帧量级（对照 control_size.rs 的经验分布）。
            assert!(
                rule.len_hi <= 1000,
                "rule {}: len_hi {} 已超出 HEADERS / 小 DATA 帧量级",
                idx,
                rule.len_hi
            );
            assert_eq!(rule.expect_responses, 0, "rule {}: 必须 F:0", idx);
            assert_eq!(rule.fake_jitter, 0);
            if let DelaySpec::LogNormal { mu_ms, sigma_ms } = rule.delay {
                let median = mu_ms.exp();
                assert!(
                    (0.5..=50.0).contains(&median),
                    "rule {}: 延迟中位数 {}ms 不在真实网络 IAT 量级",
                    idx,
                    median
                );
                assert!((0.3..=1.0).contains(&sigma_ms));
            }
        }
        assert!(
            parsed.stop.saturating_mul(MAX_SCRIPT_CYCLES_DEN)
                <= parsed.rules.len() as u64 * MAX_SCRIPT_CYCLES_NUM,
            "stop={} 超出规则数的 1.5 倍",
            parsed.stop
        );
    }

    /// 参考脚本必须与内嵌默认**不同**：两者相同就等于没有去聚类效果。
    #[test]
    fn reference_script_differs_from_the_embedded_default() {
        let reference = parse_traffic_script(&lines(REFERENCE_TRAFFIC_SCRIPT)).unwrap();
        let embedded = parse_traffic_script(&lines(&[
            "stop=6",
            "0=L:200-250,D:0,F:0",
            "1=L:180-220,D:1.5-0.6,F:0",
            "2=L:250-350,D:0,F:0",
            "3=L:300-400,D:2.0-0.5,F:0",
            "4=L:200-300,D:0,F:0",
            "5=L:400-600,D:3.0-0.7,F:0",
        ]))
        .unwrap();
        let shape = |p: &ParsedScript| -> Vec<(usize, usize)> {
            p.rules.iter().map(|r| (r.len_lo, r.len_hi)).collect()
        };
        assert_ne!(shape(&reference), shape(&embedded));
    }
}
