//! Traffic script model and parser — the single canonical implementation.
//!
//! Both config validation (`shared::validate_traffic_script`) and the session
//! traffic shaper (`kanotls-session`) build on this parser, so the two can
//! never drift apart. The shaper applies its own per-connection randomization
//! pass on top of the parsed rules; that stays on the session side.

#[derive(Clone, Debug)]
pub enum DelaySpec {
    None,
    LogNormal { mu_ms: f64, sigma_ms: f64 },
}

#[derive(Clone, Debug)]
pub struct ScriptRule {
    pub len_lo: usize,
    pub len_hi: usize,
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
/// connection, sampled once here at parse time as `base + U[0, range]`.
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

    let (len_lo, len_hi) =
        len_range.ok_or_else(|| format!("missing L field in '{}'", body))?;
    Ok(ScriptRule {
        len_lo,
        len_hi,
        delay,
        expect_responses: fake_response,
        fake_jitter,
    })
}

fn parse_len_spec(rest: &str) -> Result<(usize, usize), String> {
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
        Ok((lo, hi))
    } else if let Some((base, range)) = rest.split_once('?') {
        // `?` semantics: the value is fixed for the lifetime of the
        // connection, sampled once at parse time as base + U[0, range].
        let base: usize = base
            .trim()
            .parse()
            .map_err(|e| format!("bad len base: {}", e))?;
        let range: usize = range
            .trim()
            .parse()
            .map_err(|e| format!("bad len range: {}", e))?;
        use rand::Rng;
        let fixed = base.saturating_add(rand::thread_rng().gen_range(0..=range));
        Ok((fixed, fixed))
    } else {
        // Bare `L: N` is a fixed value, lo == hi == N.
        let fixed: usize = rest
            .parse()
            .map_err(|e| format!("bad fixed len: {}", e))?;
        Ok((fixed, fixed))
    }
}

fn parse_delay_spec(rest: &str) -> Result<DelaySpec, String> {
    if rest == "0" {
        return Ok(DelaySpec::None);
    }
    if let Some((mu_s, sigma_s)) = rest.split_once('-') {
        let mu: f64 = mu_s
            .trim()
            .parse()
            .map_err(|e| format!("bad delay mu: {}", e))?;
        let sigma: f64 = sigma_s
            .trim()
            .parse()
            .map_err(|e| format!("bad delay sigma: {}", e))?;
        if sigma < 0.0 {
            return Err(format!("delay sigma {} < 0", sigma));
        }
        Ok(DelaySpec::LogNormal {
            mu_ms: mu,
            sigma_ms: sigma,
        })
    } else {
        let d: f64 = rest.parse().map_err(|e| format!("bad delay: {}", e))?;
        if d <= 0.0 {
            return Err(format!("delay {} must be positive", d));
        }
        Ok(DelaySpec::LogNormal {
            mu_ms: d.ln(),
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
        Ok((count, jitter))
    } else {
        let count: u8 = rest
            .trim()
            .parse()
            .map_err(|e| format!("bad fake: {}", e))?;
        Ok((count, 0))
    }
}

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

    #[test]
    fn parse_with_delay_and_fake() {
        let p = parse_traffic_script(&lines(&["0=L:100-200,D:10-0.5,F:3"])).unwrap();
        assert_eq!(p.rules[0].expect_responses, 3);
        match p.rules[0].delay {
            DelaySpec::LogNormal { mu_ms, sigma_ms } => {
                assert!((mu_ms - 10.0).abs() < 0.01);
                assert!((sigma_ms - 0.5).abs() < 0.01);
            }
            _ => panic!("expected LogNormal"),
        }
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
        let p = parse_traffic_script(&lines(&[" stop = 3 ", " 0 = L:150-300, D: 0, F:1 ?2 "]))
            .unwrap();
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
    fn parse_question_mark_syntax_fixed_value() {
        for _ in 0..20 {
            let p = parse_traffic_script(&lines(&["0=L:100?50,D:0,F:0"])).unwrap();
            assert_eq!(p.rules.len(), 1);
            assert_eq!(p.rules[0].len_lo, p.rules[0].len_hi);
            assert!((100..=150).contains(&p.rules[0].len_lo));
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

    #[test]
    fn parse_accepts_zero_range_lo() {
        // Unified semantics: a zero lower bound is accepted here and clamped
        // to >= 1 by the session-side randomization pass.
        let p = parse_traffic_script(&lines(&["0=L:0-100,D:0,F:0"])).unwrap();
        assert_eq!(p.rules[0].len_lo, 0);
        assert_eq!(p.rules[0].len_hi, 100);
    }
}
