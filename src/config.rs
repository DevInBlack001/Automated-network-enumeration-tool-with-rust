use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryProfile {
    pub ping: bool,
    pub tcp_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub discovery: Option<DiscoveryProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub profiles: HashMap<String, Profile>,
}

impl ConfigFile {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context("Failed to read profile config file")?;
        let config: ConfigFile = toml::from_str(&content)
            .context("Failed to parse TOML configuration")?;
        Ok(config)
    }
}

/// The final resolved configuration for the scan
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub ping_discovery: bool,
    pub tcp_ping_ports: Vec<u16>,
}

impl ScanConfig {
    pub fn merge(cli_concurrency: usize, cli_timeout: u64, profile: Option<&Profile>) -> Self {
        let mut concurrency = cli_concurrency;
        let mut timeout_ms = cli_timeout;
        let mut ping_discovery = true;
        let mut tcp_ping_ports = vec![22, 80, 443, 445]; // default fallback ports

        if let Some(prof) = profile {
            if let Some(c) = prof.concurrency {
                concurrency = c;
            }
            if let Some(t) = prof.timeout_ms {
                timeout_ms = t;
            }
            if let Some(ref disc) = prof.discovery {
                ping_discovery = disc.ping;
                tcp_ping_ports = disc.tcp_ports.clone();
            }
        }

        ScanConfig {
            concurrency,
            timeout_ms,
            ping_discovery,
            tcp_ping_ports,
        }
    }
}
