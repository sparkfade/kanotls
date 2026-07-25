use crate::model::{Outbound, ServerConfig, ServerInbound};
use crate::shared::{
    is_placeholder_password, validate_dns_hostname, validate_log_config, validate_routing_rules,
    validate_session_config,
};
use anyhow::{bail, Result};

pub fn load_server_config(path: &str) -> Result<ServerConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: ServerConfig = serde_json::from_str(&content)?;
    validate_server_config(&config, path)?;
    Ok(config)
}

pub fn validate_server_config(config: &ServerConfig, config_path: &str) -> Result<()> {
    if config.inbounds.is_empty() {
        bail!("at least one inbound is required");
    }

    if let Some(log) = config.log.as_ref() {
        validate_log_config(log)?;
    }

    for (i, inbound) in config.inbounds.iter().enumerate() {
        validate_server_inbound(inbound, i, config_path)?;
    }

    for (i, outbound) in config.outbounds.iter().enumerate() {
        validate_server_outbound(outbound, i)?;
    }

    if let Some(routing) = config.routing.as_ref() {
        let inbound_user_map: std::collections::HashMap<
            &str,
            std::collections::HashSet<String>,
        > = config
            .inbounds
            .iter()
            .filter_map(|inbound| {
                let tag = inbound.tag.as_deref()?;
                let users = inbound
                    .settings
                    .users
                    .iter()
                    .map(|user| user.name.clone())
                    .collect();
                Some((tag, users))
            })
            .collect();
        validate_routing_rules(
            routing,
            config
                .inbounds
                .iter()
                .filter_map(|inbound| inbound.tag.as_deref()),
            config
                .outbounds
                .iter()
                .filter_map(|outbound| outbound.tag.as_deref()),
            |tag| inbound_user_map.get(tag),
        )?;
    }

    Ok(())
}

fn validate_server_inbound(inbound: &ServerInbound, idx: usize, config_path: &str) -> Result<()> {
    let prefix = format!("inbounds[{}]", idx);

    if inbound.protocol != "kanotls" {
        bail!(
            "{}: only 'kanotls' protocol is supported for server inbounds",
            prefix
        );
    }
    if inbound.port == 0 {
        bail!("{}: inbound port must not be 0", prefix);
    }

    let s = &inbound.settings;

    if s.users.is_empty() {
        bail!("{}: settings.users must not be empty", prefix);
    }
    let mut seen_names = std::collections::HashSet::new();
    let mut seen_passwords = std::collections::HashSet::new();
    for (user_idx, user) in s.users.iter().enumerate() {
        let user_prefix = format!("{}.settings.users[{}]", prefix, user_idx);
        if user.name.trim().is_empty() {
            bail!("{}: name must not be empty", user_prefix);
        }
        if !seen_names.insert(user.name.as_str()) {
            bail!("{}: duplicate user name '{}'", user_prefix, user.name);
        }
        if is_placeholder_password(&user.password) {
            bail!(
                "Detected unmodified default skeleton config.\n\
                 Please edit {} and replace the placeholder password.\n\
                 Generate a secure password: openssl rand -base64 48",
                config_path
            );
        }
        if user.password.len() < 32 {
            bail!(
                "{}: password must be at least 32 bytes (got {})",
                user_prefix,
                user.password.len()
            );
        }
        if !seen_passwords.insert(user.password.as_str()) {
            bail!(
                "{}: duplicate password (user '{}'); each user must have a distinct password",
                user_prefix,
                user.name
            );
        }
    }

    if s.camouflage.host.is_empty() {
        bail!("{}: camouflage.host is required", prefix);
    }
    validate_dns_hostname(
        &s.camouflage.host,
        &format!("{}.camouflage.host", prefix),
        "camouflage host",
    )?;

    if s.camouflage.port == 0 {
        bail!("{}: camouflage.port is required", prefix);
    }

    if let Some(session) = s.session.as_ref() {
        validate_session_config(&prefix, session)?;
    }

    Ok(())
}

fn validate_server_outbound(outbound: &Outbound, idx: usize) -> Result<()> {
    let prefix = format!("outbounds[{}]", idx);
    match outbound.protocol.as_str() {
        "direct" => {}
        "socks5" => {
            let s = outbound
                .settings
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("{}: socks5 requires settings", prefix))?;

            let _addr = s
                .get("address")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("{}: socks5 requires non-empty settings.address", prefix)
                })?;

            let port = s
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("{}: socks5 requires settings.port", prefix))?;
            if !(1..=65535).contains(&port) {
                bail!(
                    "{}: socks5 settings.port must be in 1..=65535 (got {})",
                    prefix,
                    port
                );
            }

            let has_username = s
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            let has_password = s
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if has_username && !has_password {
                bail!("{}: socks5 has username but missing password", prefix);
            }
            if !has_username && has_password {
                bail!("{}: socks5 has password but missing username", prefix);
            }
        }
        other => bail!("{}: unsupported protocol '{}'", prefix, other),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CamouflageConfig, KanotlsServerSettings, Routing, RoutingRule, ServerConfig, ServerInbound,
        User,
    };

    fn user(name: &str, password: &str) -> User {
        User {
            name: name.to_string(),
            password: password.to_string(),
        }
    }

    const PW_A: &str = "password-a-0123456789-0123456789-abcdef";
    const PW_B: &str = "password-b-0123456789-0123456789-abcdef";
    const PW_C: &str = "password-c-0123456789-0123456789-abcdef";

    fn server_config(users: Vec<User>, routing: Option<Routing>) -> ServerConfig {
        ServerConfig {
            log: None,
            inbounds: vec![ServerInbound {
                tag: Some("tls-in".to_string()),
                listen: "0.0.0.0".to_string(),
                port: 443,
                protocol: "kanotls".to_string(),
                settings: KanotlsServerSettings {
                    users,
                    camouflage: CamouflageConfig {
                        host: "example.com".to_string(),
                        port: 443,
                    },
                    session: None,
                },
            }],
            outbounds: vec![
                Outbound {
                    tag: Some("direct".to_string()),
                    protocol: "direct".to_string(),
                    settings: None,
                },
                Outbound {
                    tag: Some("socks-out".to_string()),
                    protocol: "socks5".to_string(),
                    settings: Some(serde_json::json!({
                        "address": "127.0.0.1",
                        "port": 1080
                    })),
                },
            ],
            routing,
        }
    }

    #[test]
    fn valid_multi_user_config_is_accepted() {
        let config = server_config(
            vec![user("1", PW_A), user("2", PW_B), user("3", PW_C)],
            None,
        );
        assert!(validate_server_config(&config, "test.json").is_ok());
    }

    #[test]
    fn empty_users_is_rejected() {
        let config = server_config(vec![], None);
        let err = validate_server_config(&config, "test.json").unwrap_err();
        assert!(err.to_string().contains("users must not be empty"));
    }

    #[test]
    fn duplicate_user_name_is_rejected() {
        let config = server_config(vec![user("1", PW_A), user("1", PW_B)], None);
        let err = validate_server_config(&config, "test.json").unwrap_err();
        assert!(err.to_string().contains("duplicate user name '1'"));
    }

    #[test]
    fn duplicate_password_is_rejected() {
        let config = server_config(vec![user("1", PW_A), user("2", PW_A)], None);
        let err = validate_server_config(&config, "test.json").unwrap_err();
        assert!(err.to_string().contains("duplicate password"));
    }

    #[test]
    fn short_password_is_rejected() {
        let config = server_config(vec![user("1", "too-short")], None);
        let err = validate_server_config(&config, "test.json").unwrap_err();
        assert!(err.to_string().contains("at least 32 bytes"));
    }

    #[test]
    fn legacy_tunnel_protocol_is_rejected() {
        let mut config = server_config(vec![user("1", PW_A)], None);
        config.inbounds[0].protocol = "tunnel".to_string();
        let err = validate_server_config(&config, "test.json").unwrap_err();
        assert!(err.to_string().contains("only 'kanotls' protocol"));
    }

    #[test]
    fn routing_rule_with_unknown_auth_user_is_rejected() {
        let routing = Routing {
            rules: vec![RoutingRule {
                inbound: vec!["tls-in".to_string()],
                auth_user: Some(vec!["ghost".to_string()]),
                outbound: "socks-out".to_string(),
            }],
        };
        let config = server_config(vec![user("1", PW_A), user("2", PW_B)], Some(routing));
        let err = validate_server_config(&config, "test.json").unwrap_err();
        assert!(err.to_string().contains("auth_user 'ghost'"));
    }

    #[test]
    fn routing_rule_with_known_auth_users_is_accepted() {
        let routing = Routing {
            rules: vec![
                RoutingRule {
                    inbound: vec!["tls-in".to_string()],
                    auth_user: Some(vec!["1".to_string(), "2".to_string()]),
                    outbound: "socks-out".to_string(),
                },
                RoutingRule {
                    inbound: vec!["tls-in".to_string()],
                    auth_user: None,
                    outbound: "direct".to_string(),
                },
            ],
        };
        let config = server_config(vec![user("1", PW_A), user("2", PW_B)], Some(routing));
        assert!(validate_server_config(&config, "test.json").is_ok());
    }
}
