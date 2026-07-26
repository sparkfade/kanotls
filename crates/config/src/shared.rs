use anyhow::{bail, Result};

const MAX_STREAMS_PER_SESSION_LIMIT: usize = 4096;
const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;

pub fn validate_session_config(prefix: &str, session: &crate::model::SessionConfig) -> Result<()> {
    if session.max_streams_per_session == 0
        || session.max_streams_per_session > MAX_STREAMS_PER_SESSION_LIMIT
    {
        bail!(
            "{}: session.max_streams_per_session must be in 1..={}",
            prefix,
            MAX_STREAMS_PER_SESSION_LIMIT
        );
    }
    if session.idle_timeout_secs == 0 || session.idle_timeout_secs > MAX_IDLE_TIMEOUT_SECS {
        bail!(
            "{}: session.idle_timeout_secs must be in 1..={}",
            prefix,
            MAX_IDLE_TIMEOUT_SECS
        );
    }
    if let Some(ref script) = session.traffic_script {
        validate_traffic_script(prefix, script);
    }
    if let Some(ref mode) = session.post_script_shaping {
        validate_post_script_shaping(prefix, mode);
    }
    Ok(())
}

fn validate_post_script_shaping(prefix: &str, mode: &str) {
    if !matches!(mode, "markov" | "off") {
        tracing::warn!(
            "{}: session.post_script_shaping '{}' is invalid (expected \"markov\" or \"off\"); the default \"markov\" behavior will be used instead",
            prefix,
            mode
        );
    }
}

fn validate_traffic_script(prefix: &str, script: &[String]) {
    // 与 session 侧共用同一解析实现（crate::script::parse_traffic_script），
    // 校验结果即 shaper 的实际行为：解析失败则回退内嵌默认脚本。
    if let Err(e) = crate::script::parse_traffic_script(script) {
        tracing::warn!(
            "{}: traffic_script is malformed ({}); the embedded default script will be used instead",
            prefix,
            e
        );
    }
}

pub fn is_placeholder_password(pw: &str) -> bool {
    let lower = pw.to_ascii_lowercase();
    lower.contains("change_me")
        || lower.contains("placeholder")
        || lower.contains("replace_me")
        || lower.contains("your_password_here")
        || lower.contains("fill_me")
}

pub fn validate_log_config(log: &crate::model::LogConfig) -> Result<()> {
    if let Some(level) = log.level.as_deref() {
        match level.trim().to_ascii_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => bail!(
                "log.level must be one of trace/debug/info/warn/error (got '{}')",
                other
            ),
        }
    }

    Ok(())
}

pub fn validate_routing_rules<'a>(
    routing: &crate::model::Routing,
    inbound_tags: impl Iterator<Item = &'a str>,
    outbound_tags: impl Iterator<Item = &'a str>,
    inbound_users: impl Fn(&str) -> Option<&'a std::collections::HashSet<String>>,
) -> Result<()> {
    let inbound_tags: std::collections::HashSet<_> = inbound_tags.collect();
    let outbound_tags: std::collections::HashSet<_> = outbound_tags.collect();

    for (idx, rule) in routing.rules.iter().enumerate() {
        let prefix = format!("routing.rules[{}]", idx);

        if rule.inbound.is_empty() {
            bail!("{}: inbound must not be empty", prefix);
        }
        if rule.outbound.trim().is_empty() {
            bail!("{}: outbound is required", prefix);
        }

        for inbound_tag in &rule.inbound {
            if !inbound_tags.contains(inbound_tag.as_str()) {
                bail!(
                    "{}: inbound '{}' does not match any configured inbound tag",
                    prefix,
                    inbound_tag
                );
            }
        }

        if !outbound_tags.contains(rule.outbound.as_str()) {
            bail!(
                "{}: outbound '{}' does not match any configured outbound tag",
                prefix,
                rule.outbound
            );
        }

        if let Some(auth_user) = rule.auth_user.as_ref() {
            if auth_user.is_empty() {
                bail!(
                    "{}: auth_user must not be empty (omit it to match all users)",
                    prefix
                );
            }
            let known_users: std::collections::HashSet<&str> = rule
                .inbound
                .iter()
                .filter_map(|tag| inbound_users(tag.as_str()))
                .flatten()
                .map(|name| name.as_str())
                .collect();
            for user in auth_user {
                if !known_users.contains(user.as_str()) {
                    bail!(
                        "{}: auth_user '{}' does not match any user of the referenced inbounds",
                        prefix,
                        user
                    );
                }
            }
        }
    }

    Ok(())
}

pub fn find_routing_rule<'a>(
    routing: Option<&'a crate::model::Routing>,
    inbound_tag: Option<&str>,
    auth_user: Option<&str>,
) -> Option<&'a crate::model::RoutingRule> {
    let inbound_tag = inbound_tag?;
    routing?.rules.iter().find(|rule| {
        rule.inbound.iter().any(|tag| tag.as_str() == inbound_tag)
            && match (rule.auth_user.as_ref(), auth_user) {
                (None, _) => true,
                (Some(users), _) if users.is_empty() => true,
                (Some(users), Some(user)) => users.iter().any(|u| u == user),
                (Some(_), None) => false,
            }
    })
}

pub fn validate_dns_hostname(host: &str, field: &str, kind: &str) -> Result<()> {
    if host.ends_with('.') {
        bail!("{}: DNS hostname must not have a trailing dot", field);
    }
    if host.is_empty() || host.len() > 253 {
        bail!("{}: invalid DNS hostname length", field);
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        bail!("{}: IP literals are not supported for {}", field, kind);
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("{}: invalid DNS label length", field);
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            bail!("{}: DNS labels must not start or end with '-'", field);
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            bail!("{}: DNS hostname must be ASCII LDH form", field);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_with_post_script_shaping(mode: Option<&str>) -> crate::model::SessionConfig {
        crate::model::SessionConfig {
            post_script_shaping: mode.map(|m| m.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn post_script_shaping_accepts_markov_and_off() {
        for mode in [Some("markov"), Some("off"), None] {
            let session = session_with_post_script_shaping(mode);
            assert!(validate_session_config("test", &session).is_ok());
        }
    }

    #[test]
    fn post_script_shaping_invalid_value_is_non_fatal() {
        // Invalid values only trigger a warning and are treated as unset
        // (the default "markov" behavior); validation must not fail.
        let session = session_with_post_script_shaping(Some("bogus"));
        assert!(validate_session_config("test", &session).is_ok());
    }

    fn rule(inbound: &[&str], auth_user: Option<&[&str]>, outbound: &str) -> crate::model::RoutingRule {
        crate::model::RoutingRule {
            inbound: inbound.iter().map(|s| s.to_string()).collect(),
            auth_user: auth_user
                .map(|users| users.iter().map(|s| s.to_string()).collect()),
            outbound: outbound.to_string(),
        }
    }

    fn routing(rules: Vec<crate::model::RoutingRule>) -> crate::model::Routing {
        crate::model::Routing { rules }
    }

    fn user_map<'a>(users: &'a std::collections::HashSet<String>) -> impl Fn(&str) -> Option<&'a std::collections::HashSet<String>> {
        move |tag| (tag == "tls-in").then_some(users)
    }

    #[test]
    fn find_routing_rule_prefers_auth_user_rule_over_catch_all() {
        let rules = routing(vec![
            rule(&["tls-in"], Some(&["1", "2"]), "socks-out"),
            rule(&["tls-in"], None, "direct"),
        ]);

        let matched = find_routing_rule(Some(&rules), Some("tls-in"), Some("1")).unwrap();
        assert_eq!(matched.outbound, "socks-out");
        let matched = find_routing_rule(Some(&rules), Some("tls-in"), Some("2")).unwrap();
        assert_eq!(matched.outbound, "socks-out");

        let matched = find_routing_rule(Some(&rules), Some("tls-in"), Some("3")).unwrap();
        assert_eq!(matched.outbound, "direct");
    }

    #[test]
    fn find_routing_rule_catch_all_matches_any_user() {
        let rules = routing(vec![rule(&["tls-in"], None, "direct")]);
        for user in [Some("1"), Some("whoever"), None] {
            let matched = find_routing_rule(Some(&rules), Some("tls-in"), user).unwrap();
            assert_eq!(matched.outbound, "direct");
        }
    }

    #[test]
    fn find_routing_rule_user_scoped_rule_does_not_match_without_user() {
        let rules = routing(vec![rule(&["tls-in"], Some(&["1"]), "socks-out")]);
        assert!(find_routing_rule(Some(&rules), Some("tls-in"), None).is_none());
        assert!(find_routing_rule(Some(&rules), Some("tls-in"), Some("2")).is_none());
        assert!(find_routing_rule(Some(&rules), Some("other-in"), Some("1")).is_none());
    }

    #[test]
    fn validate_routing_rules_accepts_known_auth_users() {
        let users: std::collections::HashSet<String> = ["1", "2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rules = routing(vec![
            rule(&["tls-in"], Some(&["1", "2"]), "direct"),
            rule(&["tls-in"], None, "direct"),
        ]);
        assert!(validate_routing_rules(
            &rules,
            ["tls-in"].into_iter(),
            ["direct"].into_iter(),
            user_map(&users),
        )
        .is_ok());
    }

    #[test]
    fn validate_routing_rules_rejects_unknown_auth_user() {
        let users: std::collections::HashSet<String> = ["1"].iter().map(|s| s.to_string()).collect();
        let rules = routing(vec![rule(&["tls-in"], Some(&["ghost"]), "direct")]);
        let err = validate_routing_rules(
            &rules,
            ["tls-in"].into_iter(),
            ["direct"].into_iter(),
            user_map(&users),
        )
        .unwrap_err();
        assert!(err.to_string().contains("auth_user 'ghost'"));
    }

    #[test]
    fn validate_routing_rules_rejects_empty_auth_user_list() {
        let users: std::collections::HashSet<String> = ["1"].iter().map(|s| s.to_string()).collect();
        let rules = routing(vec![rule(&["tls-in"], Some(&[]), "direct")]);
        let err = validate_routing_rules(
            &rules,
            ["tls-in"].into_iter(),
            ["direct"].into_iter(),
            user_map(&users),
        )
        .unwrap_err();
        assert!(err.to_string().contains("auth_user must not be empty"));
    }

    #[test]
    fn validate_routing_rules_rejects_unknown_inbound_and_outbound() {
        let users: std::collections::HashSet<String> = ["1"].iter().map(|s| s.to_string()).collect();
        let rules = routing(vec![rule(&["nope-in"], None, "direct")]);
        assert!(validate_routing_rules(
            &rules,
            ["tls-in"].into_iter(),
            ["direct"].into_iter(),
            user_map(&users),
        )
        .is_err());

        let rules = routing(vec![rule(&["tls-in"], None, "nope-out")]);
        assert!(validate_routing_rules(
            &rules,
            ["tls-in"].into_iter(),
            ["direct"].into_iter(),
            user_map(&users),
        )
        .is_err());
    }
}
