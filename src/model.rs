use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// CPE identifiers for the identified service (e.g. "cpe:/a:openbsd:openssh:9.6"),
    /// sourced from Nmap's `-sV` detection. Empty when Nmap enrichment didn't run
    /// or didn't produce a CPE match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
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
    /// Enumeration findings gathered by protocol-specific modules (DNS, SMB,
    /// SNMP, HTTP, TLS, ...). Empty on scans that only performed port scanning.
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// How severe a `Finding` is, in increasing order of urgency. Ord/PartialOrd
/// follow declaration order, so `Severity::Critical > Severity::Info` etc. —
/// used to sort/filter findings for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The enumeration module that produced a `Finding`. Matches the protocol
/// modules planned for the enumeration branch (DNS, SMB, SNMP, HTTP, TLS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingProtocol {
    Dns,
    Smb,
    Snmp,
    Http,
    Tls,
}

/// A single piece of enumeration output: a discovered fact about a host that's
/// worth surfacing on its own, beyond a plain open port (e.g. an SMB null
/// session, a DNS zone transfer, a default SNMP community string).
///
/// `id` is a stable, human-readable identifier chosen by the producing module
/// (e.g. "dns:axfr:10.0.0.5:example.com") rather than a random UUID, so that
/// the same finding gets the same id across repeated scans of the same
/// target — this is what diff mode will match findings on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub host: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub protocol: FindingProtocol,
    pub severity: Severity,
    /// Confidence that this finding is a true positive, 0-100 — same scale as
    /// `PortResult::confidence`.
    pub confidence: u8,
    /// Raw response snippet or other evidence backing this finding.
    pub evidence: String,
    /// Suggested defensive/hardening action.
    pub recommendation: String,
    /// External references (e.g. CWE or MITRE ATT&CK technique IDs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Unix timestamp (seconds) when the finding was recorded.
    pub timestamp: u64,
}

impl Finding {
    /// Seconds since the Unix epoch, for stamping a `Finding` at creation time.
    #[allow(dead_code)]
    pub fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_info_below_critical() {
        assert!(Severity::Critical > Severity::Info);
        assert!(Severity::High > Severity::Medium);
    }

    #[test]
    fn finding_round_trips_through_json() {
        let finding = Finding {
            id: "dns:axfr:10.0.0.5:example.com".to_string(),
            host: "10.0.0.5".parse().unwrap(),
            port: Some(53),
            protocol: FindingProtocol::Dns,
            severity: Severity::High,
            confidence: 90,
            evidence: "AXFR succeeded, transferred 42 records".to_string(),
            recommendation: "Restrict zone transfers to authorized secondaries".to_string(),
            references: vec!["CWE-200".to_string()],
            timestamp: 1_700_000_000,
        };

        let json = serde_json::to_string(&finding).expect("Finding must serialize");
        let back: Finding = serde_json::from_str(&json).expect("Finding must deserialize");
        assert_eq!(back.id, finding.id);
        assert_eq!(back.severity, Severity::High);
        assert_eq!(back.protocol, FindingProtocol::Dns);
    }

    #[test]
    fn scan_result_summary_defaults_findings_when_absent_from_json() {
        // Older JSON output predating the `findings` field must still deserialize.
        let json = r#"{"targets_scanned":1,"hosts_up":1,"duration_ms":10,"hosts":[]}"#;
        let summary: ScanResultSummary = serde_json::from_str(json).expect("must deserialize without findings");
        assert!(summary.findings.is_empty());
    }
}
