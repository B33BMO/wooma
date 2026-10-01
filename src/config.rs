use std::path::PathBuf;

use serde::Deserialize;

/// `~/.config/wooma/config.toml`, every field optional:
///
/// ```toml
/// abuseipdb_key = "..."
/// ```
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub abuseipdb_key: Option<String>,
}

pub fn path() -> PathBuf {
    if let Some(p) = std::env::var_os("WOOMA_CONFIG") {
        return p.into();
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_default();
    base.join("wooma").join("config.toml")
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let p = path();
        let mut cfg: Config = match std::fs::read_to_string(&p) {
            Ok(text) => toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?,
            Err(_) => Config::default(),
        };
        if let Ok(key) = std::env::var("ABUSEIPDB_KEY") {
            cfg.abuseipdb_key = Some(key);
        }
        cfg.abuseipdb_key = cfg.abuseipdb_key.filter(|k| !k.trim().is_empty());
        Ok(cfg)
    }
}
