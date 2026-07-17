use crate::model::{ClientConfig, ClientInbound, ClientOutbound};
use crate::shared::{
    is_placeholder_password, validate_dns_hostname, validate_log_config, validate_routing_rules,
    validate_session_config,
};
use anyhow::{bail, Result};

pub fn load_client_config(path: &str) -> Result<ClientConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: ClientConfig = serde_json::from_str(&content)?;
    validate_client_config(&config, path)?;
    Ok(config)
}

pub fn validate_client_config(config: &ClientConfig, config_path: &str) -> Result<()> {
    if config.inbounds.is_empty() {
        bail!("at least one inbound is required");
    }
    if config.outbounds.is_empty() {
        bail!("at least one outbound is required");
    }

    if let Some(log) = config.log.as_ref() {
        validate_log_config(log)?;
    }

    for (i, inbound) in config.inbounds.iter().enumerate() {
        validate_client_inbound(inbound, i)?;
    }

    for (i, outbound) in config.outbounds.iter().enumerate() {
        validate_client_outbound(outbound, i, config_path)?;
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

fn validate_client_inbound(inbound: &ClientInbound, idx: usize) -> Result<()> {
    let prefix = format!("inbounds[{}]", idx);
    match inbound.protocol.as_str() {
        "socks5" | "socks" | "http" => {}
        other => bail!(
            "{}: unsupported protocol '{}', expected 'socks5' or 'http'",
            prefix,
            other
        ),
    }
    if inbound.port == 0 {
        bail!("{}: inbound port must not be 0", prefix);
    }
    let listen = inbound.listen.trim();
    if listen.is_empty() {
        bail!("{}: listen address is required", prefix);
    }
    let addr: std::net::IpAddr = listen.parse().map_err(|_| {
        anyhow::anyhow!("{}: listen must be an IP literal, got '{}'", prefix, listen)
    })?;
    if !addr.is_loopback() {
        bail!(
            "{}: listen must be a loopback address (got '{}'). Binding to non-loopback exposes the proxy to the network.",
            prefix,
            addr
        );
    }
    Ok(())
}

fn validate_client_outbound(
    outbound: &ClientOutbound,
    idx: usize,
    config_path: &str,
) -> Result<()> {
    let prefix = format!("outbounds[{}]", idx);

    if outbound.protocol != "tunnel" {
        bail!(
            "{}: only 'tunnel' protocol is supported for client outbounds",
            prefix
        );
    }

    let s = &outbound.settings;

    if s.server.is_empty() {
        bail!("{}: server address is required", prefix);
    }

    if s.port == 0 {
        bail!("{}: server port must not be 0", prefix);
    }

    if is_placeholder_password(&s.password) {
        bail!(
            "Detected unmodified default skeleton config.\n\
             Please edit {} and replace the placeholder password.\n\
             Generate a secure password: openssl rand -base64 48",
            config_path
        );
    }
    if s.password.len() < 32 {
        bail!(
            "{}: password must be at least 32 bytes (got {})",
            prefix,
            s.password.len()
        );
    }

    if s.tls.sni.is_empty() {
        bail!("{}: tls.sni is required", prefix);
    }
    validate_dns_hostname(&s.tls.sni, &format!("{}.tls.sni", prefix), "camouflage SNI")?;

    if let Some(fingerprint) = s.tls.fingerprint.as_deref() {
        if crate::normalize_tls_fingerprint(fingerprint).is_none() {
            bail!(
                "{}: unsupported tls.fingerprint '{}', expected one of: {}",
                prefix,
                fingerprint,
                crate::SUPPORTED_TLS_FINGERPRINTS.join(", ")
            );
        }
    }

    if s.tls.template_path.is_some() {
        // template_path is validated at load time in the client runtime; nothing to
        // check here beyond presence.
    }

    if let Some(session) = s.session.as_ref() {
        validate_session_config(&prefix, session)?;
    }

    Ok(())
}
