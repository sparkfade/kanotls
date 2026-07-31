use anyhow::{bail, Result};

const MAX_STREAMS_PER_SESSION_LIMIT: usize = 4096;
const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;

/// 客户端连接池的空闲拆除上限（Firefox `network.http.keep-alive.timeout`，
/// `crates/pool/src/behavior.rs` 的 `IDLE_DRAIN_SECS`）。服务端空闲拆除与之
/// 比较决定「谁先关」。
const CLIENT_POOL_IDLE_DRAIN_SECS: u64 = 115;

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
    // 服务端空闲拆除（仅服务端生效，`!is_client` 门控）与客户端连接池的
    // 115s drain 一起决定空闲连接的「先关方」。默认 75s < 115s 保证先关方是
    // 服务端（与真实 H2 一致）；≥115s 时客户端先关——真实 Firefox 自己的
    // keep-alive 上限也是这么做的，因此这不是检测面，只是内部一致性偏好，
    // 只提示、不拒绝。
    if session.idle_timeout_secs >= CLIENT_POOL_IDLE_DRAIN_SECS {
        tracing::warn!(
            "{}: session.idle_timeout_secs = {} is not less than the client pool's {}s idle drain: \
             on an idle connection the **client** will close first instead of the server. Real \
             Firefox does the same (its own keep-alive timeout fires first), so this is not a \
             detection surface — but the 'server closes first' invariant is deliberately broken.",
            prefix,
            session.idle_timeout_secs,
            CLIENT_POOL_IDLE_DRAIN_SECS
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

/// `post_script_shaping` 的取值校验。
///
/// 此前只在取值**非法**时告警，合法取值 `"off"` 完全静默。但 `"off"` 不是一个
/// 中性开关：`packet_seq` 达到 `stop` 之后，后续每条记录按当前积压的**精确**
/// 长度发出（零延迟、无融合窗口、无 Markov 机），于是明文长度 1:1 映射到线速
/// 长度——那正是 v1.1 声称已经消除的那条特征，也是论文观测的直接输入
/// （`Wo = 25` 个包的 TCP 载荷字节序列）。默认脚本只有 6 条规则，观测窗口里
/// 绝大多数包因此都在 `"off"` 语义下。现补一条安全警告。
fn validate_post_script_shaping(prefix: &str, mode: &str) {
    match mode {
        "markov" => {}
        "off" => {
            tracing::warn!(
                "{}: session.post_script_shaping = \"off\" disables all shaping once the script is \
                 exhausted: every further record carries the exact pending backlog size, so the \
                 plaintext length maps 1:1 onto the on-wire record length. That is precisely the \
                 correlation the shaped-record design removes, and it is the direct input to the \
                 paper's Wo = 25 packet-size sequence. Only use it for throughput benchmarking, \
                 never on a censored path.",
                prefix
            );
        }
        other => {
            tracing::warn!(
                "{}: session.post_script_shaping '{}' is invalid (expected \"markov\" or \"off\"); the default \"markov\" behavior will be used instead",
                prefix,
                other
            );
        }
    }
}

/// `traffic_script` 的校验分两层：
///
/// 1. **语法** —— 与 session 侧共用同一解析实现
///    （`crate::script::parse_traffic_script`），校验结果即 shaper 的实际行为：
///    解析失败则回退内嵌默认脚本。
/// 2. **语义**（本轮新增）—— 解析成功的脚本仍可能主动制造论文的判别特征
///    （L1 类记录、开场 PING 对、跨 MTU 记录、周期性自相关）。此前这一层完全
///    不存在：一份语法合法但会把这个部署单独暴露出来的脚本可以静默上线。
///
/// 语义问题一律只告警、不改变行为，理由见 `script::lint_traffic_script`：解析
/// 失败会回退内嵌默认，把这个部署重新推回「全世界跑同一份默认」的群体，而那
/// 正是自定义脚本存在的唯一理由。
fn validate_traffic_script(prefix: &str, script: &[String]) {
    match crate::script::parse_traffic_script(script) {
        Err(e) => {
            tracing::error!(
                "{}: traffic_script is malformed ({}); this deployment is now running the \
                 embedded default script — your custom de-clustering script was discarded and \
                 every connection shares the global default profile",
                prefix,
                e
            );
        }
        Ok(parsed) => {
            for warning in crate::script::lint_traffic_script(&parsed) {
                tracing::warn!("{}: traffic_script: {}", prefix, warning);
            }
        }
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

    fn session_with_script(entries: &[&str]) -> crate::model::SessionConfig {
        crate::model::SessionConfig {
            traffic_script: Some(entries.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        }
    }

    /// 语义校验只告警、不改变返回值：一份语法合法但会制造判别特征的脚本仍然
    /// 启动成功（解析失败才回退内嵌默认，而回退会把部署推回群体默认）。
    #[test]
    fn traffic_script_semantic_problems_are_non_fatal() {
        // L1 类 + 开场 PING 对 + 跨 MTU + 4.3 个周期，四条警告全中。
        let session = session_with_script(&[
            "stop=26",
            "0=L:40-80,D:0,F:1",
            "1=L:300-4000,D:0,F:0",
            "2=L:300-400,D:0,F:0",
            "3=L:300-400,D:0,F:0",
            "4=L:300-400,D:0,F:0",
            "5=L:300-400,D:0,F:0",
        ]);
        assert!(validate_session_config("test", &session).is_ok());

        let parsed =
            crate::script::parse_traffic_script(session.traffic_script.as_ref().unwrap()).unwrap();
        let warnings = crate::script::lint_traffic_script(&parsed);
        assert!(warnings.iter().any(|w| w.contains("L1 size class")));
        assert!(warnings.iter().any(|w| w.contains("PING")));
        assert!(warnings.iter().any(|w| w.contains("single-MTU-segment")));
        assert!(warnings.iter().any(|w| w.contains("rule cycle")));
    }

    /// 参考脚本走完整的配置校验路径必须零警告。
    #[test]
    fn reference_traffic_script_validates_without_warnings() {
        let session = session_with_script(crate::script::REFERENCE_TRAFFIC_SCRIPT);
        assert!(validate_session_config("test", &session).is_ok());
        let parsed =
            crate::script::parse_traffic_script(session.traffic_script.as_ref().unwrap()).unwrap();
        assert!(crate::script::lint_traffic_script(&parsed).is_empty());
    }

    /// 格式错误的脚本仍然只是警告 + 回退。
    #[test]
    fn malformed_traffic_script_is_non_fatal() {
        let session = session_with_script(&["garbage"]);
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
