use kanotls_config::script::{parse_traffic_script, DelaySpec, ParsedScript, ScriptRule};
use kanotls_tunnel::utils::sample_log_normal;
use kanotls_tunnel::{FlowDirection, SnowyStream};
use std::time::Duration;

const BULK_FAST_PATH_THRESHOLD: usize = crate::MAX_PENDING_FLUSH_SIZE / 2;

/// Per-connection randomization window for script rule lengths: each rule's
/// length bounds are scaled by an independent sample from U[0.85, 1.20].
const SCRIPT_LEN_SCALE_LO: f64 = 0.85;
const SCRIPT_LEN_SCALE_HI: f64 = 1.20;

/// 逐连接 IAT 位置扰动窗口，作用在对数空间（见 `randomize_script`）：
/// `mu += U[-0.15, 0.15]` ⟺ 中位数 × [e^-0.15, e^0.15] ≈ ×[0.86, 1.16]。
///
/// 为什么可以扰动：真实 H2 的记录间时距由网络路径 RTT 与对端应用的处理时
/// 间共同决定，这两者确实逐连接不同，故 IAT 分布的**位置**参数逐连接变化
/// 是保真的；此前 mu 原样保留，全世界跑默认配置的实例共享同一组
/// `(ln1.5, 0.6) / (ln2.0, 0.5) / (ln3.0, 0.7)`，跨连接聚合后可以把 IAT 拟合
/// 到一个精确的参数化对数正态上，这本身就是指纹。
///
/// 为什么窗口刻意很窄、且只动 mu 不动 sigma：随机化只在真实实现也确实变化
/// 的维度上才正确——同一类客户端在同一类路径上的 IAT **形状**（右偏程度）
/// 是相近的，把 sigma 也抖开等于在一个现实中近似恒定的维度上引入变化。窄
/// 窗口同时保证扰动后的分布仍落在真实网络 IAT 的形状包络内（右偏、正定、
/// 亚毫秒到数毫秒量级），不会被拉成一个「明显被随机化过」的分布。
const SCRIPT_DELAY_LOG_SHIFT: f64 = 0.15;

/// The blend window width: over this many packets after the script is
/// exhausted, the probability of falling through to the interactive
/// sampler ramps from 0% to 100%.
const SCRIPT_BLEND_WINDOW: usize = 6;

/// 连接第一条整形数据记录的载荷窗口（均匀采样）：线速尺寸
/// `data_record_wire_len(152..=248)` = 176..272 字节，严格小于 300。
///
/// 依据：USENIX Security 2024, Xue et al., *Fingerprinting Obfuscated Proxy
/// Traffic with Encapsulated TLS Handshakes* 指出，仅用「外层 TLS 握手后第一个
/// burst 的字节数 < 300」与「往返次数 < 2.5」两条规则，就能滤掉 82.5% 的正常
/// 连接而只滤掉 1.5% 的代理连接——**burst 尺寸是其中一个判别量，而 padding
/// 只能把 burst 变大、不能变小**。burst 的定义是「方向相同的连续包尺寸累加，
/// 由方向改变**或** ≥3×RTT 的间隔打断」（论文 §6.2 原文两条件并列），因此破法
/// 是让第一条记录之后立刻出现一次方向改变，见下方 `quiet_gap` 的处理。
///
/// 为什么保持窗口内变化而不取一个定值：真实 H2 的首个 HEADERS 记录尺寸随
/// 请求（URL/Cookie/头部集合）而变，本来就不是常量；取定值会换来一个跨连接
/// 稳定的整数，那是另一条判别特征。窗口与嵌入式脚本规则 0 的 `L:200-250`
/// 同量级，但上界收得更紧：`randomize_script` 的 ×1.20 缩放会把 250 顶到 300
/// （线速 324），单靠脚本规则无法保证 < 300。
///
/// 上界从 224 放宽到 248：让出方向的手段已从「同批注入一条 41 字节
/// CMD_PADDING 请求（PING）」改为「让对端按真实 H2 语义回 SETTINGS-ACK」
/// （见 `quiet_gap` 与 `Session` 的开场序列），第一个上行 burst 于是只剩这一条
/// 记录，不再需要为 PING 预留 41 字节。
const FIRST_RECORD_PAYLOAD_LO: usize = 152;
const FIRST_RECORD_PAYLOAD_HI: usize = 248;

#[derive(Clone, Copy, Debug)]
pub(crate) struct FakeSpec {
    pub responses: u8,
}

/// 稳态记录尺寸模型（脚本窗口之后）：**确定性两态**，无任何掷硬币。
///
/// * **bulk 闩锁**：`next_data_policy` 见到积压 ≥ `BULK_FAST_PATH_THRESHOLD`
///   （或 ≥ 单记录容量）即发出满载 16 KB 记录，同轮 drain 内的尾记录按精确
///   长度收尾（`bulk_run` 迟滞，见 `begin_drain`）。积压低于阈值即解锁。
/// * **交互采样**：积压低于阈值时按 `next_data_record_payload` 的截断正态
///   采样尺寸（137–1400 B），零延迟、不注入任何帧。
///
/// 这一模型取代旧的两态 Markov 机（按 `pending/256KiB` 逐条掷硬币在两态间
/// 跳转）+ 观测窗外 IAT 注入衰减带。被替换掉的随机性从来不是真实端点的
/// 可观测属性：真实 TLS 栈（nginx / Cloudflare 的 dynamic record sizing）的
/// 记录切分由**数据可得性**驱动——缓冲够大就出 16 KB 满载记录，否则出小
/// 记录——是确定性的；逐条掷硬币反而把吞吐变成了队列深度与 RNG 的函数
/// （弱 CPU 上小记录态的每字节开销约 20 倍于满载态，发送端沦为
/// app-limited，cwnd 随负载波动）。闩锁模型与真实实现对齐到同一驱动量，
/// 同时让吞吐只取决于路径本身。
///
/// 观测窗（论文 `Wo = 25`）内的形态不变：首记录（<300 B + 让出方向）、
/// 脚本尺寸与脚本自带的 IAT 规则全部保留；脚本与交互采样同属一个尺寸
/// 族，融合窗口仍在两者间平滑过渡，无分布断层。
pub(crate) struct TrafficShaper {
    direction: FlowDirection,
    packet_seq: u64,
    script: Vec<ScriptRule>,
    script_stop: u64,
    /// Deferred fake responses from positive `F:n?k` jitter:
    /// (target packet_seq, responses).
    deferred_fakes: std::collections::VecDeque<(u64, u8)>,
    post_script_off: bool,
    /// 本轮 drain 内是否刚发出过一条满载 bulk 记录。bulk 迟滞（尾记录按精确
    /// 积压长度发出）**只在 bulk 串的尾部**成立；跨 drain 保留满载语义会让
    /// 「一次 bulk 传输之后的第一个小写入」按精确长度上链，那是一条明文
    /// 长度 → 线速长度的 1:1 映射（§3.1/§3.3 声称已消除的正是它）。
    bulk_run: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ShapePolicy {
    pub target_wire_len: usize,
    pub delay: Duration,
    pub fake: Option<FakeSpec>,
    /// Fake response emitted *before* this record hits the wire (negative
    /// jitter: the fake belongs to the previous record's slot).
    pub pre_fake: Option<FakeSpec>,
    pub allow_full_block: bool,
    /// 本条记录发出后必须让出方向：写循环挂起直到对端有记录抵达（或上限
    /// 到期）。仅**客户端**连接的第一条整形数据记录置位——它把第一个上行
    /// burst 收缩到这一条记录（见 FIRST_RECORD_PAYLOAD_LO 的论证）。
    ///
    /// 让出方向不再需要注入任何帧：这条记录承载的正是 `CMD_SETTINGS`
    /// （`write_gather_open` 把 `[SETTINGS][SYN][PSH…]` 合并提交），而对端按
    /// 真实 H2 语义必须回一条 `SETTINGS` + `WINDOW_UPDATE` + `SETTINGS-ACK`
    /// 开场 flight（见 `Session::emit_h2_server_opening`），那是一个不经 DNS /
    /// connect 的帧层应答，正常路径上一个 RTT 内必到。
    pub quiet_gap: bool,
}

/// 内嵌默认脚本。
///
/// **全部规则的 `expect_responses` 现为 0**（此前规则 2 / 4 各带 `F:1`）。
/// `F:n` 会在触发记录之后插入一条 `CMD_PADDING` 请求，其线速尺寸是 PING
/// （41 字节），对端回一条 PING-ACK（41）——即在连接的第 2、第 4 条数据记录
/// 处插入一对 PING/PING-ACK。真实 H2 的 PING 是 30–150 s 量级的保活帧，不会
/// 在连接开场的头几条记录里出现；更糟的是「小的本端包 → 小的对端包」紧跟在
/// 一个下行 burst 之后就等于论文里 Distinc 2.879 的 `(−L4, L1, −L1)`。
///
/// 方向改变现在由**真实 H2 成因**提供，不再由脚本注入：
/// * 开场——客户端首条数据记录承载 `CMD_SETTINGS`，服务端按 H2 语义回
///   `SETTINGS + WINDOW_UPDATE + SETTINGS-ACK`，客户端再回 `SETTINGS-ACK`；
/// * 连接生命周期——`Session` 的合成 H2 请求/响应交换（HEADERS 尺寸的请求换
///   响应尺寸的应答），即论文所称的 "synthetic co-existing flows"；
/// * 消费字节驱动的 `WINDOW_UPDATE`（既有骨架）。
///
/// `ScriptRule::expect_responses` / `fake_jitter` 仍是配置层的公开字段，用户脚本
/// 显式写 `F:n` 时行为不变——只是默认不再使用。
fn embedded_script() -> ParsedScript {
    ParsedScript {
        rules: vec![
            ScriptRule {
                len_lo: 200,
                len_hi: 250,
                len_pinned: false,
                delay: DelaySpec::None,
                expect_responses: 0,
                fake_jitter: 0,
            },
            ScriptRule {
                len_lo: 180,
                len_hi: 220,
                len_pinned: false,
                delay: DelaySpec::LogNormal {
                    mu_ms: 1.5_f64.ln(),
                    sigma_ms: 0.6,
                },
                expect_responses: 0,
                fake_jitter: 0,
            },
            ScriptRule {
                len_lo: 250,
                len_hi: 350,
                len_pinned: false,
                delay: DelaySpec::None,
                expect_responses: 0,
                fake_jitter: 0,
            },
            ScriptRule {
                len_lo: 300,
                len_hi: 400,
                len_pinned: false,
                delay: DelaySpec::LogNormal {
                    mu_ms: 2.0_f64.ln(),
                    sigma_ms: 0.5,
                },
                expect_responses: 0,
                fake_jitter: 0,
            },
            ScriptRule {
                len_lo: 200,
                len_hi: 300,
                len_pinned: false,
                delay: DelaySpec::None,
                expect_responses: 0,
                fake_jitter: 0,
            },
            ScriptRule {
                len_lo: 400,
                len_hi: 600,
                len_pinned: false,
                delay: DelaySpec::LogNormal {
                    mu_ms: 3.0_f64.ln(),
                    sigma_ms: 0.7,
                },
                expect_responses: 0,
                fake_jitter: 0,
            },
        ],
        stop: 6,
    }
}

impl TrafficShaper {
    pub(crate) fn new(
        direction: FlowDirection,
        script_lines: Option<&[String]>,
        post_script_off: bool,
    ) -> Self {
        let ParsedScript {
            rules: mut script,
            stop,
        } = script_lines
            .map(|lines| parse_traffic_script(lines).unwrap_or_else(|_| embedded_script()))
            .unwrap_or_else(embedded_script);
        randomize_script(&mut script);
        Self {
            direction,
            packet_seq: 0,
            script,
            script_stop: stop,
            deferred_fakes: std::collections::VecDeque::new(),
            post_script_off,
            bulk_run: false,
        }
    }

    /// 一轮 `drive_shaper` 排空开始：清掉 bulk 串标记。
    ///
    /// bulk 闩锁跨 drain 由积压量重新判定（见 `next_data_policy`），而 bulk
    /// 迟滞分支（尾记录按精确积压长度发出）只对**同一串**里的尾记录成立。
    /// 若不清标记，一次 bulk 传输之后的第一个小写入（例如 20 KB 上传后紧跟
    /// 80 字节的内层 Finished）会以 `data_record_wire_len(80)` = 104 字节
    /// 上链——明文长度 1:1 映射到线速长度，而且那是一个紧跟在下行大 burst
    /// 之后的 `L1` 本端包，正是判别力最高的 `(L2, −L4, L1)` 的第三个元素。
    pub(crate) fn begin_drain(&mut self) {
        self.bulk_run = false;
    }

    #[cfg(test)]
    pub(crate) fn packet_seq(&self) -> u64 {
        self.packet_seq
    }

    /// 测试辅助：跳过连接的首条整形数据记录（首发让出方向的那一条），使
    /// 断言可以直接观察脚本 / 稳态两态的常态行为。
    #[cfg(test)]
    pub(crate) fn skip_first_flight(&mut self) {
        self.packet_seq = 1;
    }

    pub(crate) fn next_data_policy(&mut self, pending_len: usize) -> ShapePolicy {
        debug_assert!(pending_len > 0);
        let cap = SnowyStream::data_record_capacity();

        // 连接的第一条整形数据记录先于 bulk fast path 处理：fast path 会把它
        // 顶成满载记录（16406 字节），第一个上行 burst 直接爆掉 300 字节门限。
        // 客户端的首条数据记录承载的正是内层 TLS ClientHello 的开头
        // （gather-open 把 SETTINGS+SYN+target+首块合并提交），旧路径下它的线速
        // 尺寸恒等于「内层首包 + 24」——Chrome 541、带 ML-KEM 的 Firefox ~1908，
        // 是一个 1:1 的确定性映射。
        //
        // 只对 C2S 生效：论文 Figure 8 的「first burst after the TLS handshake」
        // 是**客户端**在握手后的第一个 burst（"an outgoing GET and an incoming
        // response"）。服务端方向不但不需要这个上限，强加还有害——真实服务端
        // 的第一条 application-data 记录之后是继续推响应体，不会停下来等客户端；
        // 让 S2C 也 `quiet_gap` 等于在每条流的首个响应上插一次最多 300ms 的
        // 静默，那是一个真实 nginx 不存在的形态。
        if self.packet_seq == 0 && self.direction == FlowDirection::C2S {
            use rand::Rng;
            let payload =
                rand::thread_rng().gen_range(FIRST_RECORD_PAYLOAD_LO..=FIRST_RECORD_PAYLOAD_HI);
            // post_script_off 语义是「关闭整形」，此时不让出方向（读循环的
            // H2 骨架同样被它关掉），只保留尺寸上限。
            let mut policy = ShapePolicy {
                target_wire_len: SnowyStream::data_record_wire_len(payload),
                delay: Duration::ZERO,
                fake: None,
                pre_fake: None,
                allow_full_block: false,
                quiet_gap: !self.post_script_off,
            };
            self.release_due_fakes(&mut policy);
            return policy;
        }

        if pending_len >= BULK_FAST_PATH_THRESHOLD || pending_len >= cap {
            self.bulk_run = true;
            let mut policy = ShapePolicy {
                target_wire_len: SnowyStream::max_data_record_wire_len(),
                delay: Duration::ZERO,
                fake: None,
                pre_fake: None,
                allow_full_block: true,
                quiet_gap: false,
            };
            self.release_due_fakes(&mut policy);
            return policy;
        }

        // Bulk hysteresis: the tail of a bulk burst goes out at its exact
        // size with zero delay and no fake frames — 任何延迟/注入都不得拖住
        // 一次吞吐串的收尾。`bulk_run` 限定它只在**同一轮 drain 内**紧跟
        // 满载记录时成立（见 `begin_drain`）。
        if self.bulk_run && pending_len < cap {
            self.bulk_run = false;
            let mut policy = ShapePolicy {
                target_wire_len: SnowyStream::data_record_wire_len(pending_len),
                delay: Duration::ZERO,
                fake: None,
                pre_fake: None,
                allow_full_block: false,
                quiet_gap: false,
            };
            self.release_due_fakes(&mut policy);
            return policy;
        }

        // post_script_shaping = "off": once the script is exhausted, emit
        // every further record at its exact pending size with zero delay
        // and no fake frames — no Markov machine, no blend window.
        if self.post_script_off && self.packet_seq >= self.script_stop {
            let mut policy = ShapePolicy {
                target_wire_len: SnowyStream::data_record_wire_len(pending_len),
                delay: Duration::ZERO,
                fake: None,
                pre_fake: None,
                allow_full_block: false,
                quiet_gap: false,
            };
            self.release_due_fakes(&mut policy);
            return policy;
        }

        let script_stop = self.script_stop;
        let packet_seq = self.packet_seq;

        // Smooth blend: when we are within SCRIPT_BLEND_WINDOW packets
        // past the script's stop point, the probability of using the
        // interactive sampler ramps linearly from 0 to 1. Beyond that
        // window, the script is fully bypassed.
        let script_blend_p = if packet_seq < script_stop {
            1.0_f64
        } else {
            let overshoot = packet_seq.saturating_sub(script_stop);
            1.0_f64 - (overshoot as f64 / SCRIPT_BLEND_WINDOW as f64).min(1.0)
        };

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut policy = if rng.gen::<f64>() < script_blend_p && !self.script.is_empty() {
            self.script_policy(cap)
        } else {
            self.interactive_policy()
        };
        self.release_due_fakes(&mut policy);
        policy
    }

    /// Flush deferred fake responses whose target has been reached. Once the
    /// script is exhausted (packet_seq >= stop), every remaining deferred
    /// fake becomes due immediately. Merged into the policy's post-record
    /// fake slot with u8 saturation.
    fn release_due_fakes(&mut self, policy: &mut ShapePolicy) {
        if self.deferred_fakes.is_empty() {
            return;
        }
        let seq = self.packet_seq;
        let past_script = seq >= self.script_stop;
        let mut total: u16 = policy
            .fake
            .as_ref()
            .map(|f| f.responses as u16)
            .unwrap_or(0);
        // 注意：队列**不保证**按 target 单调——`packet_seq + offset` 里的
        // offset 每条规则独立采样，后入队的条目可能带更小的 target，因此到期
        // 条目可能排在未到期条目之后，不能只截断队首。队列长度受解析器
        // `MAX_FAKE_JITTER_OFFSET` 上界约束，这里全量扫描、只保留未到期项。
        let mut retained = std::collections::VecDeque::new();
        for (target, responses) in self.deferred_fakes.drain(..) {
            if past_script || seq >= target {
                total = total.saturating_add(responses as u16);
            } else {
                retained.push_back((target, responses));
            }
        }
        self.deferred_fakes = retained;
        if total > 0 {
            policy.fake = Some(FakeSpec {
                responses: total.min(u8::MAX as u16) as u8,
            });
        }
    }

    fn script_policy(&mut self, cap: usize) -> ShapePolicy {
        let idx = (self.packet_seq as usize).wrapping_rem(self.script.len());
        let rule = &self.script[idx];

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_h2_payload = rng.gen_range(rule.len_lo..=rule.len_hi);

        // 结构性下界：数据记录的线速尺寸永不落入论文的 `L1`（≤160）。
        //
        // 此前这条钳制只在 Markov 路径生效（`next_data_record_payload` 自带
        // `MIN_DATA_RECORD_PAYLOAD` 下界），脚本路径是裸的
        // `gen_range(len_lo..=len_hi)`。于是一份写着 `L:100-200` 的用户脚本会
        // 发出线速 ≤160 的数据记录，紧跟一个下行 burst 就精确复现判别力第一的
        // `(L2, −L4, L1)`（Distinc 7.226）——启动期 lint 警告拦不住已经发出的
        // 记录，必须在这里挡住。
        //
        // 边界要按**截断后**算：`randomize_script` 的下缩放是 ×0.85 且
        // `as usize` 截断，故 `len_lo = 161` 仍会得到载荷 136 ⇒ 线速 160（危险），
        // `len_lo = 162` 才落到 137 ⇒ 线速 161。与其让操作员去记这个边界，不如
        // 在此处按 `MIN_DATA_RECORD_PAYLOAD` 无条件抬到 L1 之上。
        //
        // 钳制只加在**脚本路径**：它为每条记录独立指定尺寸，与积压量无关。
        // 另外两条会给出小记录的路径不在此列，且成因不同——bulk 迟滞的尾记录
        // 与 `post_script_shaping = off` 的精确尺寸都反映「积压真的只剩这么多」，
        // 且与前面的记录同方向、同一次 flush，构不成「方向改变后的孤立小包」。
        let floored = random_h2_payload
            .max(kanotls_tunnel::control_size::MIN_DATA_RECORD_PAYLOAD)
            .min(cap);
        let target_wire_len = SnowyStream::data_record_wire_len(floored);

        let delay = delay_from_spec(&rule.delay);

        // Fake-response position jitter: sample an offset in
        // [min(0,k), max(0,k)]. Negative = emit before this record (the
        // previous record's slot); zero = after this record; positive =
        // defer to a later record (released by release_due_fakes).
        let mut pre_fake = None;
        let mut fake = None;
        if rule.expect_responses > 0 {
            let responses = rule.expect_responses;
            let jitter = rule.fake_jitter;
            let offset: i32 = if jitter > 0 {
                rng.gen_range(0..=jitter)
            } else if jitter < 0 {
                rng.gen_range(jitter..=0)
            } else {
                0
            };
            if offset < 0 {
                pre_fake = Some(FakeSpec { responses });
            } else if offset == 0 {
                fake = Some(FakeSpec { responses });
            } else {
                self.deferred_fakes
                    .push_back((self.packet_seq + offset as u64, responses));
            }
        }

        ShapePolicy {
            target_wire_len,
            delay,
            fake,
            pre_fake,
            allow_full_block: false,
            quiet_gap: false,
        }
    }

    /// 交互采样策略：脚本窗口之外的常态小记录路径。尺寸来自
    /// `next_data_record_payload`（H2 HEADERS/DATA 帧尺寸分布），零延迟、
    /// 不注入任何帧——真实 TLS 端点把已排队的记录一次写出，记录之间没有
    /// 人为毫秒级间隔（间隔由脚本规则的 `D:` 在开场面层表达，见内嵌脚本）。
    fn interactive_policy(&mut self) -> ShapePolicy {
        // 数据记录走 H2 HEADERS/DATA 帧的尺寸分布，**不复用控制帧的离散池**
        // （旧路径 91% 落在 `{33, 37, 41, 46, 54}`，例行进入论文的 `L1` 类，
        // 复现判别力第 1 的 `(L2, −L4, L1)`；论证见 `control_size::L1_MAX_WIRE_LEN`）。
        let mut rng = rand::thread_rng();
        let payload =
            kanotls_tunnel::control_size::next_data_record_payload(self.direction, &mut rng);
        ShapePolicy {
            target_wire_len: SnowyStream::data_record_wire_len(payload),
            delay: Duration::ZERO,
            fake: None,
            pre_fake: None,
            allow_full_block: false,
            quiet_gap: false,
        }
    }

    /// `packet_seq` 的口径是「本连接已发出的整形数据记录序号」，**不是**
    /// 「脚本被应用过的次数」；`stop` 相应地是「脚本管辖到第几号记录」。
    ///
    /// 这一区分在 bulk 路径上可见：`drive_shaper` 的 sticky 满载路径只在开头
    /// 咨询一次 `next_data_policy`，其余记录用合成策略，但仍逐条 `advance()`。
    /// 于是一次大传输会把 `stop` 预算「走完」而一条脚本规则都没应用。这是
    /// **有意为之**：脚本描述的是连接开场那段交互式流量的形状，它是**位置**
    /// 模型而不是配额。若改成「只有咨询过脚本才推进」，那么一次 20 MB 上传
    /// 之后的第一个小写入会拿到规则 0 的开场尺寸——把「连接开场」的形态放在
    /// 一个真实实现绝不会出现的位置上，那比脚本没生效更可疑。
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

/// Per-connection randomization pass over a built script: rotate the rule
/// order by a random offset, then scale every rule's length window by an
/// independent U[SCRIPT_LEN_SCALE_LO, SCRIPT_LEN_SCALE_HI] sample (clamped
/// to >= 1, lo <= hi, hi <= data record capacity). This keeps the mapping
/// from "position i" to size distribution from being globally constant
/// across connections.
///
/// 每条规则的 delay 同样施加一次独立的逐连接扰动：`DelaySpec::None` 保持零
/// 延迟；`LogNormal` 只平移 `mu_ms`，且必须在对数空间做加法而不是对 mu 做
/// 乘法——mu 是对数空间的位置参数，`mu × f` 与「中位数 × f」完全不是一回事
/// （mu 接近 0 即中位数接近 1ms 时，乘法几乎不产生任何变化；mu 为负时乘法
/// 还会把中位数推向反方向）。`mu + ln f` 才等价于中位数乘 f，见
/// SCRIPT_DELAY_LOG_SHIFT 的正当性论证。
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
        // `?` 规则：窗口在此处每连接坍缩一次成固定值——这正是「连接生命周期
        // 内固定」语义的实现点（parse 保持确定性，见 `ScriptRule::len_pinned`）。
        // 坍缩后与普通规则一样再缩放，分布等价于 (base + U[0, range]) × scale。
        let (lo, hi) = if rule.len_pinned {
            let fixed = rng.gen_range(rule.len_lo..=rule.len_hi);
            (fixed, fixed)
        } else {
            (rule.len_lo, rule.len_hi)
        };
        let lo = (lo as f64 * scale) as usize;
        let hi = (hi as f64 * scale) as usize;
        rule.len_lo = lo.max(1).min(cap);
        rule.len_hi = hi.max(rule.len_lo).min(cap);

        if let DelaySpec::LogNormal { mu_ms, .. } = &mut rule.delay {
            *mu_ms += rng.gen_range(-SCRIPT_DELAY_LOG_SHIFT..=SCRIPT_DELAY_LOG_SHIFT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn question_mark_value_stable_across_policies() {
        // A `?` rule collapses once per connection at randomize time: after
        // construction the window is a fixed point, and repeated policy calls
        // must yield the same target wire length.
        // stop=8：跳过首发记录后仍有充足的脚本包数，两次查询都走脚本。
        let mut shaper = TrafficShaper::new(
            FlowDirection::C2S,
            Some(&lines(&["stop=8", "0=L:100?50"])),
            false,
        );
        assert_eq!(
            shaper.script[0].len_lo, shaper.script[0].len_hi,
            "? 规则必须在 randomize 期坍缩成固定值"
        );
        shaper.skip_first_flight();
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

    /// C7 回归：IAT 位置参数必须逐连接变化，且扰动必须窄且有界——「全随机」
    /// 与「恒定」同样是判别特征。断言中位数落在 ×[e^-0.15, e^0.15] 内、
    /// sigma（分布形状）原样不动，且跨连接确实出现了多个不同的 mu。
    #[test]
    fn randomize_script_shifts_delay_median_within_a_narrow_window() {
        // `D:2.0-0.5` 的 `2.0` 是**中位数毫秒**，parser 存的是 `ln 2.0`。此前
        // 双参数形式把它原样当对数空间的 mu 存下（`D:1.5-0.6` 的实际中位数
        // 因此是 4.48ms 而非 1.5ms），配置语法与 `embedded_script()` 里已经取过
        // ln 的 Rust 字面量语义相反；basis 现随 parser 一并改为 `ln 2.0`。
        let mu: f64 = 2.0_f64.ln();
        const SIGMA: f64 = 0.5;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..40 {
            let shaper = TrafficShaper::new(
                FlowDirection::C2S,
                Some(&lines(&["0=L:100,D:2.0-0.5,F:0"])),
                false,
            );
            let DelaySpec::LogNormal { mu_ms, sigma_ms } = shaper.script[0].delay else {
                panic!("rule must keep its LogNormal delay spec");
            };
            // mu 是对数空间的位置参数：平移量直接对应中位数的乘性缩放。
            let median_scale = (mu_ms - mu).exp();
            assert!(
                median_scale >= (-SCRIPT_DELAY_LOG_SHIFT).exp() - 1e-9
                    && median_scale <= SCRIPT_DELAY_LOG_SHIFT.exp() + 1e-9,
                "median scale {} outside the narrow per-connection window",
                median_scale
            );
            assert_eq!(sigma_ms, SIGMA, "分布形状（sigma）不参与逐连接抖动");
            seen.insert(mu_ms.to_bits());
        }
        assert!(seen.len() > 1, "delay 位置参数必须逐连接变化");
    }

    /// C7 回归：`DelaySpec::None` 必须保持零延迟——抖动不得把「这条规则不
    /// 插入间隔」变成「插入一个很小的间隔」。
    #[test]
    fn randomize_script_keeps_zero_delay_rules_at_zero() {
        for _ in 0..20 {
            let shaper = TrafficShaper::new(FlowDirection::S2C, None, false);
            let zero_rules = shaper
                .script
                .iter()
                .filter(|rule| matches!(rule.delay, DelaySpec::None))
                .count();
            // 嵌入式脚本 6 条规则里恰有 3 条 D:0，轮转/抖动都不改变这个计数。
            assert_eq!(zero_rules, 3);
            for rule in &shaper.script {
                if matches!(rule.delay, DelaySpec::None) {
                    assert_eq!(delay_from_spec(&rule.delay), Duration::ZERO);
                }
            }
        }
    }

    /// C22 回归：客户端连接的第一条整形数据记录必须 (a) 线速尺寸 < 300 字节，
    /// (b) 置位 quiet_gap 让写循环让出方向，(c) 优先于 bulk fast path，
    /// (d) **不注入任何帧**。(a)+(b) 合起来把外层握手后的第一个上行 burst 压到
    /// 300 字节以下（判别依据见 FIRST_RECORD_PAYLOAD_LO）。
    ///
    /// (d) 是 C24 的改动：此前这条记录同批注入一条 41 字节 CMD_PADDING 请求
    /// （线速恰为 H2 PING 尺寸）来换取方向改变，于是连接的第 0 条记录是一个
    /// PING——真实 H2 的第一帧是 HEADERS，PING 是 30–150s 量级的保活帧。方向
    /// 改变现在由服务端按 H2 语义回的 SETTINGS 开场 flight 提供。
    #[test]
    fn first_data_record_stays_under_the_first_burst_threshold() {
        let cap = SnowyStream::data_record_capacity();
        let mut seen = std::collections::HashSet::new();
        // 含满载积压：first-flight 必须优先于 bulk fast path。
        for pending in [64usize, 4096, cap * 4, crate::MAX_PENDING_FLUSH_SIZE] {
            for _ in 0..40 {
                let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
                let policy = shaper.next_data_policy(pending);
                assert!(!policy.allow_full_block, "首发记录不得走满载 fast path");
                assert!(
                    policy.target_wire_len < 300,
                    "首条记录 {} 必须 < 300",
                    policy.target_wire_len
                );
                assert!(policy.quiet_gap, "首条记录必须让出方向");
                assert!(
                    policy.fake.is_none() && policy.pre_fake.is_none(),
                    "首条记录不得注入任何 CMD_PADDING（PING）帧"
                );
                assert_eq!(policy.delay, Duration::ZERO);
                seen.insert(policy.target_wire_len);

                // 第二条起回到常态：不再让出方向。
                shaper.advance();
                let next = shaper.next_data_policy(pending);
                assert!(!next.quiet_gap);
            }
        }
        assert!(seen.len() > 1, "首条记录尺寸必须跨连接变化，不能是常量");
    }

    /// C24：first-burst 上限与让出方向只对 C2S 生效。论文 Figure 8 量的是
    /// **客户端**在外层握手后的第一个 burst（"an outgoing GET and an incoming
    /// response"）；真实服务端发出第一条 application-data 记录后是继续推响应体，
    /// 不会停下来等客户端，因此 S2C 强加 quiet_gap 反而是一个 nginx 不存在的
    /// 形态（每条流的首个响应上多出一次最多 300ms 的静默）。
    #[test]
    fn first_record_hand_over_is_client_direction_only() {
        for _ in 0..40 {
            let mut shaper = TrafficShaper::new(FlowDirection::S2C, None, false);
            let policy = shaper.next_data_policy(4096);
            assert!(!policy.quiet_gap, "服务端方向不得让出方向");
            assert!(policy.fake.is_none() && policy.pre_fake.is_none());
        }
    }

    /// post_script_off（整形整体关闭）时不让出方向——与读循环里被同一开关关掉
    /// 的 H2 骨架保持一致；尺寸上限仍然保留。
    #[test]
    fn first_data_record_hand_over_is_gated_by_post_script_off() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, true);
        let policy = shaper.next_data_policy(4096);
        assert!(policy.fake.is_none());
        assert!(!policy.quiet_gap);
        assert!(policy.target_wire_len < 300);
    }

    #[test]
    fn embedded_script_has_rules() {
        let script = embedded_script();
        assert!(!script.rules.is_empty());
        for rule in &script.rules {
            assert!(rule.len_lo > 0);
            assert!(rule.len_hi >= rule.len_lo);
        }
    }

    #[test]
    fn full_backlog_anchors_to_full_record() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
        shaper.skip_first_flight();
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
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&lines(&["0=L:500"])), false);
        shaper.skip_first_flight();
        assert!(
            shaper
                .next_data_policy(BULK_FAST_PATH_THRESHOLD)
                .allow_full_block
        );
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&lines(&["0=L:500"])), false);
        shaper.skip_first_flight();
        assert!(shaper.next_data_policy(cap).allow_full_block);
    }

    /// 结构性不变量：**任何**脚本（含故意写小的）产出的数据记录，线速尺寸
    /// 恒 > `L1_MAX_WIRE_LEN`（160）。
    ///
    /// L1 类的数据记录紧跟一个下行 burst 就是判别力第一的 `(L2, −L4, L1)`
    /// （Distinc 7.226）。这是安全下界而不是可配置偏好：操作员的意图在「负载
    /// 形状」维度被尊重，但不得突破它。边界取 `randomize_script` 的 ×0.85
    /// 下缩放 + `as usize` 截断之后的实际值——`L:161` 仍会落到线速 160。
    #[test]
    fn script_data_records_never_land_in_the_l1_class() {
        use kanotls_tunnel::control_size::L1_MAX_WIRE_LEN;
        // 覆盖到危险边界两侧：161 是截断后仍落在 L1 的最大值，162 才安全。
        for rule in [
            "0=L:1",
            "0=L:1-2",
            "0=L:50-120",
            "0=L:100-200",
            "0=L:160",
            "0=L:161",
            "0=L:162",
        ] {
            for direction in [FlowDirection::C2S, FlowDirection::S2C] {
                for _ in 0..200 {
                    let mut shaper =
                        TrafficShaper::new(direction, Some(&lines(&["stop=32", rule])), false);
                    shaper.skip_first_flight();
                    // 覆盖脚本窗口与其后的融合/交互采样窗口。每条记录各起一轮
                    // drain（`begin_drain` 清 bulk 串标记），对应「小写入各自
                    // 排空」这一形态——也正是 L1 记录会成为**孤立小包**的形态。
                    // bulk 迟滞的尾记录不在此不变量内：它只可能紧跟在同方向的
                    // 满载记录之后（论证见 script_policy 的钳制注释）。
                    for _ in 0..40 {
                        shaper.begin_drain();
                        let policy = shaper.next_data_policy(64);
                        assert!(
                            policy.target_wire_len > L1_MAX_WIRE_LEN,
                            "规则 {} 产出线速 {} 落入 L1 类",
                            rule,
                            policy.target_wire_len
                        );
                        shaper.advance();
                    }
                }
            }
        }
    }

    #[test]
    fn script_policy_applies_from_first_data_record() {
        // The handshake bypass is gone: the script applies from the record
        // right after the first-flight record (packet_seq=1). The single fixed
        // rule "L:500" is only scaled by the randomization pass (U[0.85, 1.20]).
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&lines(&["0=L:500"])), false);
        assert_eq!(shaper.packet_seq(), 0);
        shaper.skip_first_flight();
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
        // Bulk hysteresis: the tail of a bulk burst (bulk_run set,
        // pending < cap) is emitted at its exact wire length, with zero
        // delay and no fake frames, and the shaper leaves bulk mode.
        let mut shaper = TrafficShaper::new(FlowDirection::S2C, None, false);
        shaper.skip_first_flight();
        // 同一轮 drain 内紧跟满载记录：`bulk_run` 是迟滞生效的前提。
        shaper.bulk_run = true;
        let policy = shaper.next_data_policy(1234);
        assert_eq!(
            policy.target_wire_len,
            SnowyStream::data_record_wire_len(1234)
        );
        assert_eq!(policy.delay, Duration::ZERO);
        assert!(policy.fake.is_none());
        assert!(!policy.allow_full_block);
        assert!(!shaper.bulk_run, "迟滞只服务同串尾记录，用过即清");
    }

    #[test]
    fn off_mode_uses_script_until_exhausted() {
        // post_script_off does not disable the script itself: while
        // packet_seq < stop, script policy still applies. The
        // single fixed rule "L:500" is only scaled by the
        // randomization pass (U[0.85, 1.20]).
        let mut shaper = TrafficShaper::new(
            FlowDirection::C2S,
            Some(&lines(&["stop=8", "0=L:500"])),
            true,
        );
        assert_eq!(shaper.packet_seq(), 0);
        shaper.skip_first_flight();
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
        // Once packet_seq reaches stop, off mode emits every record
        // at its exact pending size with zero delay and no fake frames —
        // no Markov machine, no blend window.
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&lines(&["0=L:500"])), true);
        shaper.packet_seq = shaper.script_stop;
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
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&lines(&["0=L:500"])), true);
        shaper.packet_seq = shaper.script_stop;
        assert!(
            shaper
                .next_data_policy(BULK_FAST_PATH_THRESHOLD)
                .allow_full_block
        );
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, Some(&lines(&["0=L:500"])), true);
        shaper.packet_seq = shaper.script_stop;
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
    fn bulk_latch_engages_on_full_backlog_and_releases_on_drain_out() {
        let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
        // 推过脚本 + 融合窗口，确保走的是稳态两态而不是脚本。
        shaper.packet_seq = shaper.script_stop + SCRIPT_BLEND_WINDOW as u64;
        // 积压 ≥ 阈值 ⇒ 满载闩锁（确定性，不掷硬币）。
        let policy = shaper.next_data_policy(crate::MAX_PENDING_FLUSH_SIZE);
        assert!(policy.allow_full_block);
        assert!(shaper.bulk_run);
        shaper.advance();
        // 同轮 drain 内的尾记录：精确尺寸收尾。
        let tail = shaper.next_data_policy(3000);
        assert_eq!(
            tail.target_wire_len,
            SnowyStream::data_record_wire_len(3000)
        );
        assert!(!tail.allow_full_block);
        shaper.advance();
        // 新的一轮 drain、小积压 ⇒ 解锁回交互采样：尺寸被采样器夹到
        // 与积压无关的包络内（≤1400 载荷），且**不等于**精确积压。
        shaper.begin_drain();
        for _ in 0..20 {
            let policy = shaper.next_data_policy(3000);
            assert!(!policy.allow_full_block);
            assert!(policy.target_wire_len <= SnowyStream::data_record_wire_len(1400));
            assert_ne!(
                policy.target_wire_len,
                SnowyStream::data_record_wire_len(3000),
                "小积压不得再沿用满载/精确语义"
            );
            shaper.advance();
        }
    }

    #[test]
    fn interactive_policy_emits_zero_delay_and_no_frames() {
        let mut shaper = TrafficShaper::new(FlowDirection::S2C, None, false);
        shaper.packet_seq = shaper.script_stop + SCRIPT_BLEND_WINDOW as u64;
        for _ in 0..50 {
            let policy = shaper.next_data_policy(64);
            assert_eq!(policy.delay, Duration::ZERO);
            assert!(policy.fake.is_none() && policy.pre_fake.is_none());
            assert!(!policy.quiet_gap);
            shaper.advance();
        }
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
        let shaper = TrafficShaper::new(
            FlowDirection::C2S,
            Some(&lines(&["0=L:400-500,D:0,F:0"])),
            false,
        );
        assert_eq!(shaper.script.len(), 1);
        assert_eq!(shaper.script_stop, 1);
        // The randomization pass scales both bounds by one U[0.85, 1.20]
        // sample: lo stays within [340, 480], hi within [425, 600].
        assert!((340..=480).contains(&shaper.script[0].len_lo));
        assert!((425..=600).contains(&shaper.script[0].len_hi));
        assert!(shaper.script[0].len_lo <= shaper.script[0].len_hi);
    }

    #[test]
    fn new_falls_back_on_bad_script() {
        let shaper = TrafficShaper::new(FlowDirection::C2S, Some(&lines(&["garbage"])), false);
        assert!(!shaper.script.is_empty());
    }

    #[test]
    fn stop_cycles_rules_until_reached() {
        // stop=4 with 2 rules: packets 0..4 cycle rules[seq % 2]; at
        // packet_seq == stop the blend window begins.
        let mut shaper = TrafficShaper::new(
            FlowDirection::C2S,
            Some(&lines(&["stop=4", "0=L:100", "1=L:200"])),
            false,
        );
        assert_eq!(shaper.script_stop, 4);
        for expected_seq in 0..4u64 {
            assert_eq!(shaper.packet_seq(), expected_seq);
            let policy = shaper.next_data_policy(50);
            assert!(!policy.allow_full_block);
            shaper.advance();
        }
        assert_eq!(shaper.packet_seq(), 4);
    }

    #[test]
    fn fake_jitter_zero_pins_to_current_record() {
        let mut shaper = TrafficShaper::new(
            FlowDirection::C2S,
            Some(&lines(&["0=L:100,D:0,F:2"])),
            false,
        );
        shaper.skip_first_flight();
        let policy = shaper.next_data_policy(50);
        assert!(policy.pre_fake.is_none());
        assert_eq!(policy.fake.map(|f| f.responses), Some(2));
        assert!(shaper.deferred_fakes.is_empty());
    }

    #[test]
    fn fake_jitter_negative_emits_pre_or_post() {
        // F:1?-1: offset in {-1, 0} — the fake is attached to this record
        // either pre or post; never deferred.
        let mut shaper = TrafficShaper::new(
            FlowDirection::C2S,
            Some(&lines(&["0=L:100,D:0,F:1?-1"])),
            false,
        );
        shaper.skip_first_flight();
        let mut seen_pre = false;
        let mut seen_post = false;
        for _ in 0..60 {
            let policy = shaper.next_data_policy(50);
            let pre = policy.pre_fake.is_some();
            let post = policy.fake.is_some();
            assert!(pre != post, "exactly one of pre/post fake must be set");
            seen_pre |= pre;
            seen_post |= post;
            assert!(shaper.deferred_fakes.is_empty());
            // 回到 1 而非 0：packet_seq==0 是首发让出方向的那一条记录，不走脚本。
            shaper.packet_seq = 1;
        }
        assert!(seen_pre && seen_post, "both offsets must occur");
    }

    #[test]
    fn fake_jitter_positive_defers_until_target_or_stop() {
        // F:1?2: offset in {0, 1, 2} — deferred fakes are released at their
        // target, and every remaining one is flushed once the script is
        // exhausted (packet_seq >= stop). At seq == stop the blend
        // probability is still 1.0, so a third scripted sample occurs and
        // is released immediately.
        for _ in 0..40 {
            let mut shaper = TrafficShaper::new(
                FlowDirection::C2S,
                Some(&lines(&["stop=2", "0=L:100,D:0,F:1?2"])),
                false,
            );
            let mut total: u16 = 0;
            for _ in 0..3 {
                let policy = shaper.next_data_policy(50);
                total += policy.fake.map(|f| f.responses as u16).unwrap_or(0);
                total += policy.pre_fake.map(|f| f.responses as u16).unwrap_or(0);
                shaper.advance();
            }
            // 2：两条脚本记录各产生一份，最迟在 packet_seq >= stop 时全部释放。
            // （packet_seq==0 的首发记录不再注入任何 fake 请求，见 C24。）
            assert_eq!(total, 2, "all fakes released by stop");
            assert!(shaper.deferred_fakes.is_empty());
        }
    }

    /// C24 验收 1（分布独立性）：first-flight 记录的尺寸窗口必须与积压量
    /// **无关**——否则「第一个上行 burst 的取值范围」就能反推内层首包长度。
    /// 逐个积压量各取 200 组样本，断言四组样本落在同一个声明窗口里、且每组都
    /// 铺开了这个窗口的绝大部分（不是各占一个子区间）。
    #[test]
    fn first_flight_size_distribution_is_independent_of_backlog() {
        let cap = SnowyStream::data_record_capacity();
        let lo = SnowyStream::data_record_wire_len(FIRST_RECORD_PAYLOAD_LO);
        let hi = SnowyStream::data_record_wire_len(FIRST_RECORD_PAYLOAD_HI);
        for pending in [64usize, 4096, cap * 4, crate::MAX_PENDING_FLUSH_SIZE] {
            let mut seen = Vec::new();
            for _ in 0..200 {
                let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
                seen.push(shaper.next_data_policy(pending).target_wire_len);
            }
            let observed_lo = *seen.iter().min().expect("non-empty");
            let observed_hi = *seen.iter().max().expect("non-empty");
            assert!(
                observed_lo >= lo && observed_hi <= hi,
                "pending={} 的 first-flight 尺寸 [{}, {}] 越出窗口 [{}, {}]",
                pending,
                observed_lo,
                observed_hi,
                lo,
                hi
            );
            // 200 组样本必须铺开窗口的 ≥80%：若某个积压量把尺寸压进一个子区间，
            // 那就是一条积压量 → 尺寸的可观测相关性。
            let span = observed_hi - observed_lo;
            assert!(
                span * 5 >= (hi - lo) * 4,
                "pending={} 的 first-flight 尺寸只铺开 {}/{}，与积压量相关",
                pending,
                span,
                hi - lo
            );
        }
    }

    /// C24 验收 3：观测窗口（论文 `Wo = 25`）内的每一条数据记录都必须由 shaper
    /// 定尺寸，**不存在「尺寸直接等于积压」的窗口**。
    ///
    /// 判据做成确定性的而不是逐样本比对：脚本与交互采样的尺寸分布有一个**与积压
    /// 无关**的上界（脚本 `len_hi × 1.20` 最大 720，交互采样上界 1400，两者加
    /// `MIN_DATA_WIRE_LEN`），因此只要每次都喂一个**超过那个上界**的亚容量积压，
    /// 「尺寸 == 积压」就必然越界被抓到；逐样本 `assert_ne!` 反而会因为分布支撑集
    /// 恰好覆盖积压长度而误报。
    ///
    /// 覆盖三个策略区段：脚本（`packet_seq < stop`）、融合窗口、纯交互采样。唯一
    /// 允许「尺寸 == 精确积压」的是 bulk 串的尾记录，而那需要同一轮 drain 内刚
    /// 发过一条满载记录——真实 TLS 端点把一次 write 的余量写成一条恰好那么大的
    /// record，那一条是保真而非泄漏。
    #[test]
    fn every_record_in_the_observation_window_is_shaper_sized() {
        const WO: usize = 25;
        let l1_max = kanotls_tunnel::control_size::L1_MAX_WIRE_LEN;
        // 与积压无关的尺寸上界：脚本的 600 × 1.20 = 720，交互采样的 1400。
        let envelope_hi = SnowyStream::data_record_wire_len(1400);
        let full = SnowyStream::max_data_record_wire_len();
        let mut saw_script = false;
        let mut saw_interactive = false;
        for direction in [FlowDirection::C2S, FlowDirection::S2C] {
            for _ in 0..40 {
                let mut shaper = TrafficShaper::new(direction, None, false);
                shaper.begin_drain();
                let mut prev_full_block = false;
                for seq in 0..WO {
                    // 每条记录的积压都 > envelope_hi 且 < 容量：任何 1:1 映射
                    // 都会把尺寸顶到包络之外。
                    let pending = 2000 + seq * 400;
                    assert!(pending > envelope_hi && pending < SnowyStream::data_record_capacity());
                    let policy = shaper.next_data_policy(pending);
                    if seq < shaper.script_stop as usize {
                        saw_script = true;
                    }
                    if seq >= shaper.script_stop as usize + SCRIPT_BLEND_WINDOW {
                        saw_interactive = true;
                    }
                    let exact = SnowyStream::data_record_wire_len(pending);
                    let ok = policy.target_wire_len <= envelope_hi
                        || policy.target_wire_len == full
                        || (prev_full_block && policy.target_wire_len == exact);
                    assert!(
                        ok,
                        "seq={} 的记录尺寸 {} 越出与积压无关的包络（积压 {}，1:1 会是 {}）",
                        seq, policy.target_wire_len, pending, exact
                    );
                    assert!(
                        policy.target_wire_len > l1_max,
                        "seq={} 的数据记录 {} 落在论文的 L1 类",
                        seq,
                        policy.target_wire_len
                    );
                    prev_full_block = policy.allow_full_block;
                    shaper.advance();
                }
            }
        }
        assert!(
            saw_script && saw_interactive,
            "必须覆盖脚本段与纯交互采样段"
        );
    }

    /// C24：bulk 迟滞（尾记录按精确积压长度发出）只在**同一轮 drain 内**紧跟
    /// 满载记录时成立。跨 drain 保留满载语义会让「一次 bulk 传输之后的第一个
    /// 小写入」按精确长度上链——那既是一条明文长度 → 线速长度的 1:1 映射，
    /// 也是一个紧跟在下行大 burst 之后的 `L1` 本端包
    /// （`(L2, −L4, L1)` 的第三个元素）。
    #[test]
    fn bulk_hysteresis_does_not_leak_the_next_drains_small_write() {
        let cap = SnowyStream::data_record_capacity();
        for _ in 0..40 {
            let mut shaper = TrafficShaper::new(FlowDirection::C2S, None, false);
            shaper.skip_first_flight();
            // 一轮 drain：满载闩锁把 bulk_run 置位。
            shaper.begin_drain();
            assert!(shaper.next_data_policy(cap * 4).allow_full_block);
            shaper.advance();

            // 新的一轮 drain：80 字节的小写入（内层 Finished 量级）不得按
            // 精确长度上链。
            shaper.begin_drain();
            let policy = shaper.next_data_policy(80);
            assert_ne!(
                policy.target_wire_len,
                SnowyStream::data_record_wire_len(80),
                "bulk 之后的第一个小写入按精确长度上链，泄漏明文长度"
            );
            assert!(
                policy.target_wire_len > kanotls_tunnel::control_size::L1_MAX_WIRE_LEN,
                "bulk 之后的第一个小写入 {} 落在 L1 类",
                policy.target_wire_len
            );
        }
    }

    /// C24：内嵌默认脚本不再注入任何 `CMD_PADDING` 请求。`F:n` 会在触发记录后
    /// 插入一对 PING/PING-ACK（41/41），而真实 H2 的 PING 是 30–150s 量级的
    /// 保活帧，不会出现在连接开场的头几条记录里。
    #[test]
    fn embedded_script_injects_no_fake_interaction_frames() {
        let script = embedded_script();
        for (i, rule) in script.rules.iter().enumerate() {
            assert_eq!(
                rule.expect_responses, 0,
                "内嵌脚本规则 {} 仍注入 fake 请求",
                i
            );
            assert_eq!(rule.fake_jitter, 0);
        }
        // 用户脚本显式写 F:n 时行为不变（配置层的公开字段仍然生效）。
        let mut shaper = TrafficShaper::new(
            FlowDirection::C2S,
            Some(&lines(&["0=L:300,D:0,F:2"])),
            false,
        );
        shaper.skip_first_flight();
        assert_eq!(
            shaper.next_data_policy(50).fake.map(|f| f.responses),
            Some(2)
        );
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
