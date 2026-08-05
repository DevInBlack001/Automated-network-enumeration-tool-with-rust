use serde::{Serialize, Deserialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    /// No response was received (common for UDP probes): the port may be open
    /// behind a firewall, or genuinely open but silent for the probe sent.
    #[serde(rename = "open|filtered")]
    OpenFiltered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// How a `PortResult`'s `service` name was determined, in decreasing order of
/// reliability. Lets consumers of the report judge how much to trust the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceSource {
    /// Identified via Nmap's `-sV` probe/signature matching.
    NmapProbe,
    /// Identified from a live response via content-based signature matching
    /// (e.g. an "SSH-" prefix, an HTTP status line) — not a port-number guess.
    NativeBanner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub status: PortStatus,
    pub protocol: TransportProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Confidence in `service`, on a 0-100 scale. Absent when `service` is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_source: Option<ServiceSource>,
}

/// Best-guess OS identification for a host, sourced from Nmap's `-O` detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    /// Nmap's own match accuracy, 0-100.
    pub accuracy: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub status: HostStatus,
    pub ports: Vec<PortResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultSummary {
    pub targets_scanned: usize,
    pub hosts_up: usize,
    pub duration_ms: u64,
    pub hosts: Vec<HostResult>,
}
