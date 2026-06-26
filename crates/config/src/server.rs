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
        )?;
    }

    Ok(())
}

fn validate_server_inbound(inbound: &ServerInbound, idx: usize, config_path: &str) -> Result<()> {
    let prefix = format!("inbounds[{}]", idx);

    if inbound.protocol != "tunnel" {
        bail!(
            "{}: only 'tunnel' protocol is supported for server inbounds",
            prefix
        );
    }
    if inbound.port == 0 {
        bail!("{}: inbound port must not be 0", prefix);
    }

    let s = &inbound.settings;

    if s.password.len() < 32 {
        if is_placeholder_password(&s.password) {
            bail!(
                "Detected unmodified default skeleton config.\n\
                 Please edit {} and replace the placeholder password.\n\
                 Generate a secure password: openssl rand -base64 48",
                config_path
            );
        }
        bail!(
            "{}: password must be at least 32 bytes (got {})",
            prefix,
            s.password.len()
        );
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
