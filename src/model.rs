use serde::{Serialize, Deserialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub status: PortStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub status: HostStatus,
    pub ports: Vec<PortResult>,
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
