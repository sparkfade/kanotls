mod client;
mod server;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "kanotls",
    version = env!("CARGO_PKG_VERSION"),
    about = "Experimental TLS + Noise tunnel"
)]
pub struct Opt {
    #[arg(short, long)]
    pub config: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let config_path = find_config_file(opt.config.as_deref())?;
    let config_content = std::fs::read_to_string(&config_path)?;
    let log_level = resolve_log_level(&config_content)?;

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .init();

    match detect_mode(&config_content) {
        Ok(Mode::Server) => server::run_server(&config_path).await,
        Ok(Mode::Client) => client::run_client(&config_path).await,
        Err(e) => {
            eprintln!("cannot detect mode: {}", e);
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Server,
    Client,
}

fn detect_mode(config_content: &str) -> anyhow::Result<Mode> {
    let v: serde_json::Value = serde_json::from_str(config_content)?;
    let mut saw_server = false;
    let mut saw_client = false;

    if let Some(inbounds) = v.get("inbounds") {
        if let Some(inbounds) = inbounds.as_array() {
            for inbound in inbounds {
                if let Some(protocol) = inbound.get("protocol") {
                    let p = protocol.as_str().unwrap_or("");
                    if p == "tunnel" {
                        if let Some(settings) = inbound.get("settings") {
                            if settings.get("camouflage").is_some()
                                || settings.get("reference").is_some()
                            {
                                saw_server = true;
                            }
                        }
                    }
                    if p == "socks5" || p == "socks" || p == "http" {
                        saw_client = true;
                    }
                }
            }
        }
    }

    match (saw_server, saw_client) {
        (true, false) => Ok(Mode::Server),
        (false, true) => Ok(Mode::Client),
        (true, true) => anyhow::bail!(
            "config matches both server and client layouts; keep tunnel camouflage in server configs and socks5/http in client configs"
        ),
        (false, false) => anyhow::bail!(
            "config must contain either a tunnel inbound with camouflage/reference or a socks5/http inbound"
        ),
    }
}

fn find_config_file(explicit: Option<&str>) -> anyhow::Result<String> {
    if let Some(path) = explicit {
        check_file_readable(path)?;
        return Ok(path.to_string());
    }

    #[cfg(target_os = "linux")]
    let system_path = "/etc/kanotls/config.json";
    #[cfg(target_os = "macos")]
    let system_path = "/usr/local/etc/kanotls/config.json";

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match std::fs::File::open(system_path) {
            Ok(_) => return Ok(system_path.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                anyhow::bail!(
                    "system config {} exists but is not readable (permission denied). \
                     Check file permissions or run with appropriate privileges.",
                    system_path
                );
            }
            Err(e) => {
                anyhow::bail!("cannot access system config {}: {}", system_path, e);
            }
        }
    }

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let sibling_path = exe_dir.join("config.json");
    check_file_readable(&sibling_path.to_string_lossy())?;
    Ok(sibling_path.to_string_lossy().to_string())
}

fn check_file_readable(path: &str) -> anyhow::Result<()> {
    match std::fs::File::open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("config file not found: {}", path);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!("cannot read config {}: permission denied", path);
        }
        Err(e) => {
            anyhow::bail!("cannot access config {}: {}", path, e);
        }
    }
}

fn resolve_log_level(config_content: &str) -> anyhow::Result<String> {
    let value: serde_json::Value = serde_json::from_str(config_content)?;
    let config_level = value
        .get("log")
        .and_then(|log| log.get("level"))
        .and_then(|level| level.as_str())
        .map(str::trim)
        .filter(|level| !level.is_empty())
        .map(str::to_ascii_lowercase);

    if let Some(level) = config_level {
        validate_log_level(&level)?;
        return Ok(level);
    }

    match std::env::var("RUST_LOG") {
        Ok(level) if !level.trim().is_empty() => Ok(level),
        _ => Ok("info".to_string()),
    }
}

fn validate_log_level(level: &str) -> anyhow::Result<()> {
    match level {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => anyhow::bail!(
            "invalid log.level '{}': expected trace/debug/info/warn/error",
            level
        ),
    }
}
