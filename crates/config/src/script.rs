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
}

/// Parse a whole traffic script into rules. Blank lines and `#` comments are
/// skipped; a script with no rules at all is rejected (the caller falls back
/// to the embedded default script). Error messages carry the 1-based line
/// number of the offending rule.
///
/// `Length: base?range` semantics: the value is fixed for the lifetime of the
/// connection, sampled once here at parse time as `base + U[0, range]`.
pub fn parse_traffic_script(text: &str) -> Result<Vec<ScriptRule>, String> {
    let mut rules = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rule = parse_script_line(line).map_err(|e| format!("line {}: {}", idx + 1, e))?;
        rules.push(rule);
    }
    if rules.is_empty() {
        return Err("script contains no rules".to_string());
    }
    Ok(rules)
}

fn parse_script_line(line: &str) -> Result<ScriptRule, String> {
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
                len_range = Some((fixed, fixed));
            } else {
                // Bare `Length: N` is a fixed value, lo == hi == N.
                let fixed: usize = rest
                    .parse()
                    .map_err(|e| format!("bad fixed len: {}", e))?;
                len_range = Some((fixed, fixed));
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
    Ok(ScriptRule {
        len_lo,
        len_hi,
        delay,
        expect_responses: fake_response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_rule() {
        let rules = parse_traffic_script("Length: 200~250, Delay: 0, FakeResponse: 0").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].len_lo, 200);
        assert_eq!(rules[0].len_hi, 250);
        assert_eq!(rules[0].expect_responses, 0);
    }

    #[test]
    fn parse_with_fake_response() {
        let rules = parse_traffic_script("Length: 100~200, Delay: 10~0.5, FakeResponse: 3").unwrap();
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
        let rules = parse_traffic_script(text).unwrap();
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
        let rules = parse_traffic_script(text).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parse_rejects_inverted_range() {
        assert!(parse_traffic_script("Length: 250~200, Delay: 0, FakeResponse: 0").is_err());
    }

    #[test]
    fn parse_rejects_missing_length() {
        assert!(parse_traffic_script("Delay: 0, FakeResponse: 0").is_err());
    }

    #[test]
    fn parse_rejects_empty_or_comment_only_script() {
        assert!(parse_traffic_script("").is_err());
        assert!(parse_traffic_script("  \n\n").is_err());
        assert!(parse_traffic_script("# only a comment\n").is_err());
    }

    #[test]
    fn parse_question_mark_syntax_fixed_value() {
        for _ in 0..20 {
            let rules = parse_traffic_script("Length: 100?50, Delay: 0, FakeResponse: 0").unwrap();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].len_lo, rules[0].len_hi);
            assert!((100..=150).contains(&rules[0].len_lo));
        }
    }

    #[test]
    fn parse_bare_number_fixed_value() {
        let rules = parse_traffic_script("Length: 333, Delay: 0, FakeResponse: 0").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].len_lo, 333);
        assert_eq!(rules[0].len_hi, 333);
    }

    #[test]
    fn parse_accepts_zero_range_lo() {
        // Unified semantics: a zero lower bound is accepted here and clamped
        // to >= 1 by the session-side randomization pass.
        let rules = parse_traffic_script("Length: 0~100, Delay: 0, FakeResponse: 0").unwrap();
        assert_eq!(rules[0].len_lo, 0);
        assert_eq!(rules[0].len_hi, 100);
    }

    #[test]
    fn parse_error_reports_line_number() {
        let text = "\
Length: 200~250, Delay: 0, FakeResponse: 0
Length: 250~200, Delay: 0, FakeResponse: 0
";
        let err = parse_traffic_script(text).unwrap_err();
        assert!(err.starts_with("line 2: "), "error must name the line: {}", err);
    }
}
