use std::sync::Arc;

use anyhow::Context;
use rustls::crypto::ring::{cipher_suite, default_provider, kx_group};
use rustls::crypto::CryptoProvider;
use rustls::ClientConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FingerprintPreset {
    Rustls,
    Firefox,
    PythonOpenSsl,
}

pub fn make_dangerous_client_config(
    fingerprint: Option<&str>,
) -> Result<ClientConfig, anyhow::Error> {
    let provider = make_provider(fingerprint)?;
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to build dangerous client config")?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(
            crate::utils::NoCertificateVerification,
        ))
        .with_no_client_auth();

    Ok(config)
}

pub fn make_verified_client_config(
    fingerprint: Option<&str>,
) -> Result<ClientConfig, anyhow::Error> {
    let provider = make_provider(fingerprint)?;
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed to build verified client config")?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

pub(crate) fn fingerprint_preset(
    fingerprint: Option<&str>,
) -> Result<FingerprintPreset, anyhow::Error> {
    Ok(parse_optional_fingerprint(fingerprint)?.unwrap_or(FingerprintPreset::Firefox))
}

pub fn alpn_protocols_for_fingerprint(
    fingerprint: Option<&str>,
) -> Result<Vec<Vec<u8>>, anyhow::Error> {
    let preset = parse_optional_fingerprint(fingerprint)?;
    match preset.unwrap_or(FingerprintPreset::Firefox) {
        FingerprintPreset::Firefox => Ok(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        FingerprintPreset::Rustls => Ok(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        FingerprintPreset::PythonOpenSsl => Ok(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    }
}

fn make_provider(fingerprint: Option<&str>) -> Result<CryptoProvider, anyhow::Error> {
    let preset = parse_optional_fingerprint(fingerprint)?;
    let mut provider = default_provider();

    match preset.unwrap_or(FingerprintPreset::Firefox) {
        FingerprintPreset::Rustls => {
            provider.cipher_suites = vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ];
            provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
        }
        FingerprintPreset::Firefox => {
            provider.cipher_suites = vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
            ];
            provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1];
        }
        FingerprintPreset::PythonOpenSsl => {
            provider.cipher_suites = vec![
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
            provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1];
        }
    }

    Ok(provider)
}

fn parse_optional_fingerprint(
    fingerprint: Option<&str>,
) -> Result<Option<FingerprintPreset>, anyhow::Error> {
    fingerprint.map(parse_fingerprint).transpose()
}

fn parse_fingerprint(fingerprint: &str) -> Result<FingerprintPreset, anyhow::Error> {
    match fingerprint.trim().to_ascii_lowercase().as_str() {
        "rustls" => Ok(FingerprintPreset::Rustls),
        "firefox" => Ok(FingerprintPreset::Firefox),
        "python-openssl" | "baseline" => Ok(FingerprintPreset::PythonOpenSsl),
        other => anyhow::bail!(
            "unsupported tls.fingerprint '{}', expected one of: firefox, rustls, python-openssl, baseline",
            other
        ),
    }
}
