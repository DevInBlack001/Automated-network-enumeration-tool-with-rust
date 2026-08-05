use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use std::fs;
use std::net::IpAddr;
use std::str::FromStr;

/// Governs which resolved targets a scan is actually permitted to touch.
///
/// The denylist always takes precedence over the allowlist. An empty
/// allowlist means "no restriction beyond the denylist" so existing
/// single-target/CIDR workflows keep working without opting in.
#[derive(Debug, Clone, Default)]
pub struct ScopePolicy {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl ScopePolicy {
    pub fn build(
        allow: &[String],
        allow_file: &Option<String>,
        deny: &[String],
        deny_file: &Option<String>,
    ) -> Result<Self> {
        let mut allow_entries = allow.to_vec();
        if let Some(path) = allow_file {
            allow_entries.extend(read_lines(path)?);
        }

        let mut deny_entries = deny.to_vec();
        if let Some(path) = deny_file {
            deny_entries.extend(read_lines(path)?);
        }

        Ok(ScopePolicy {
            allow: parse_entries(&allow_entries)?,
            deny: parse_entries(&deny_entries)?,
        })
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|net| net.contains(&ip))
    }

    /// Splits `hosts` into (in-scope, out-of-scope), preserving relative order.
    pub fn partition(&self, hosts: Vec<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
        hosts.into_iter().partition(|ip| self.is_allowed(*ip))
    }
}

fn parse_entries(entries: &[String]) -> Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(parse_entry)
        .collect()
}

fn parse_entry(s: &str) -> Result<IpNet> {
    if let Ok(net) = IpNet::from_str(s) {
        return Ok(net);
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(IpNet::from(ip));
    }
    bail!("Invalid scope entry '{}': expected an IP address or CIDR network", s)
}

fn read_lines(path: &str) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read scope file '{}'", path))?;
    Ok(content.lines().map(str::to_string).collect())
}
