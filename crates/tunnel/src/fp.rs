/// Validate a configured `tls.fingerprint` name. Only `firefox` is
/// supported: the outer ClientHello is always built from the (stripped)
/// Firefox template, so any other value is a config error.
pub(crate) fn validate_fingerprint(fingerprint: Option<&str>) -> Result<(), anyhow::Error> {
    let Some(name) = fingerprint else {
        return Ok(());
    };
    if kanotls_config::normalize_tls_fingerprint(name).is_none() {
        anyhow::bail!(
            "unsupported tls.fingerprint '{}', expected: {}",
            name,
            kanotls_config::SUPPORTED_TLS_FINGERPRINTS.join(", ")
        );
    }
    Ok(())
}
