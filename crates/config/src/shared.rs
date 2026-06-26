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
    Ok(())
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
) -> Result<()> {
    let inbound_tags: std::collections::HashSet<_> = inbound_tags.collect();
    let outbound_tags: std::collections::HashSet<_> = outbound_tags.collect();

    for (idx, rule) in routing.rules.iter().enumerate() {
        let prefix = format!("routing.rules[{}]", idx);

        if rule.rule_type.trim().is_empty() {
            bail!("{}: type is required", prefix);
        }
        if rule.inbound_tag.is_empty() {
            bail!("{}: inbound_tag must not be empty", prefix);
        }
        if rule.outbound_tag.trim().is_empty() {
            bail!("{}: outbound_tag is required", prefix);
        }

        for inbound_tag in &rule.inbound_tag {
            if !inbound_tags.contains(inbound_tag.as_str()) {
                bail!(
                    "{}: inbound_tag '{}' does not match any configured inbound tag",
                    prefix,
                    inbound_tag
                );
            }
        }

        if !outbound_tags.contains(rule.outbound_tag.as_str()) {
            bail!(
                "{}: outbound_tag '{}' does not match any configured outbound tag",
                prefix,
                rule.outbound_tag
            );
        }
    }

    Ok(())
}

pub fn find_routing_rule<'a>(
    routing: Option<&'a crate::model::Routing>,
    inbound_tag: Option<&str>,
) -> Option<&'a crate::model::RoutingRule> {
    let inbound_tag = inbound_tag?;
    routing?.rules.iter().find(|rule| {
        rule.inbound_tag
            .iter()
            .any(|tag| tag.as_str() == inbound_tag)
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
