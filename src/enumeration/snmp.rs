use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use snmp2::{AsyncSession, Oid, Value};
use tokio::time::timeout;

use crate::model::{Finding, FindingProtocol, HostResult, PortResult, PortStatus, Severity, TransportProtocol};

/// Community strings checked, in order. Both are still shipped as the
/// factory default on a meaningful fraction of SNMP-capable devices.
const COMMUNITY_STRINGS: &[&str] = &["public", "private"];
const SYS_DESCR_OID: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_NAME_OID: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const IF_DESCR_BASE: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
const MAX_INTERFACES: usize = 32;

fn make_finding(
    id_suffix: &str,
    host: IpAddr,
    port: u16,
    severity: Severity,
    evidence: String,
    recommendation: String,
) -> Finding {
    Finding {
        id: format!("snmp:{}:{}:{}", id_suffix, host, port),
        host,
        port: Some(port),
        protocol: FindingProtocol::Snmp,
        severity,
        confidence: 100,
        evidence,
        recommendation,
        references: Vec::new(),
        timestamp: Finding::now_ts(),
    }
}

/// Runs SNMP enumeration against every open UDP port on `host` that looks
/// like SNMP (port 161, or a service name containing "snmp"): tries default
/// community strings ("public", "private") with a GET, and for each one that
/// responds, flags it and — on the first working one — gathers sysDescr,
/// sysName, and a walk of the interface table.
pub async fn enumerate_host(host: &HostResult, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();

    for port_res in &host.ports {
        // SNMP is UDP; an "open|filtered" result is the expected shape for a
        // silent UDP port that never got a real probe response either way.
        let plausibly_open = port_res.status == PortStatus::Open || port_res.status == PortStatus::OpenFiltered;
        if !plausibly_open || port_res.protocol != TransportProtocol::Udp {
            continue;
        }
        if !looks_like_snmp(port_res) {
            continue;
        }

        findings.extend(probe_port(host.ip, port_res.port, timeout_ms).await);
    }

    findings
}

fn looks_like_snmp(port_res: &PortResult) -> bool {
    if port_res.port == 161 {
        return true;
    }
    port_res
        .service
        .as_deref()
        .map(|s| s.to_lowercase().contains("snmp"))
        .unwrap_or(false)
}

async fn probe_port(ip: IpAddr, port: u16, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let addr = SocketAddr::new(ip, port).to_string();
    let t = Duration::from_millis(timeout_ms);
    let mut gathered_details = false;

    for community in COMMUNITY_STRINGS {
        let mut session = match timeout(t, AsyncSession::new_v2c(addr.as_str(), community.as_bytes(), 0)).await {
            Ok(Ok(s)) => s,
            _ => continue,
        };

        // A wrong community string makes an SNMPv1/v2c agent silently drop the
        // request rather than return an error PDU, so "did the GET complete
        // before timing out" is itself the accept/reject signal.
        let Some(sys_descr) = get_value_string(&mut session, SYS_DESCR_OID, t).await else {
            continue;
        };

        findings.push(make_finding(
            "community",
            ip,
            port,
            Severity::High,
            format!("SNMP accepted community string '{}'", community),
            "Change default SNMP community strings, restrict SNMP access via firewall/ACL to management hosts only, and migrate to SNMPv3 with authentication and encryption.".to_string(),
        ));

        if !gathered_details {
            gathered_details = true;

            findings.push(make_finding(
                "sysdescr",
                ip,
                port,
                Severity::Info,
                format!("sysDescr: {}", sys_descr),
                String::new(),
            ));

            if let Some(sys_name) = get_value_string(&mut session, SYS_NAME_OID, t).await {
                findings.push(make_finding(
                    "sysname",
                    ip,
                    port,
                    Severity::Info,
                    format!("sysName: {}", sys_name),
                    String::new(),
                ));
            }

            let interfaces = walk_interfaces(&mut session, t).await;
            if !interfaces.is_empty() {
                findings.push(make_finding(
                    "interfaces",
                    ip,
                    port,
                    Severity::Info,
                    format!("Interfaces: {}", interfaces.join(", ")),
                    String::new(),
                ));
            }
        }
    }

    findings
}

async fn get_value_string(session: &mut AsyncSession, oid_parts: &[u64], t: Duration) -> Option<String> {
    let oid = Oid::from(oid_parts).ok()?;
    let response = timeout(t, session.get(&oid)).await.ok()?.ok()?;
    response.varbinds.into_iter().next().and_then(|(_, value)| format_value(&value))
}

/// Walks the interface description table (ifDescr, 1.3.6.1.2.1.2.2.1.2) via
/// repeated GETNEXT, stopping when the walk leaves that subtree, the agent
/// signals end-of-view, or `MAX_INTERFACES` is reached (a defensive cap, not
/// an expectation -- real devices rarely have more than a handful).
async fn walk_interfaces(session: &mut AsyncSession, t: Duration) -> Vec<String> {
    let mut names = Vec::new();

    let Ok(base) = Oid::from(IF_DESCR_BASE) else {
        return names;
    };
    let base_bytes = base.as_bytes().to_vec();
    let mut current = base;

    for _ in 0..MAX_INTERFACES {
        let response = match timeout(t, session.getnext(&current)).await {
            Ok(Ok(r)) => r,
            _ => break,
        };
        let Some((oid, value)) = response.varbinds.into_iter().next() else {
            break;
        };
        if !oid.as_bytes().starts_with(base_bytes.as_slice()) {
            break;
        }
        if matches!(value, Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance) {
            break;
        }
        if let Some(name) = format_value(&value) {
            names.push(name);
        }
        current = oid.to_owned();
    }

    names
}

fn format_value(value: &Value) -> Option<String> {
    match value {
        Value::OctetString(bytes) => Some(String::from_utf8_lossy(bytes).trim_matches('\0').trim().to_string()),
        Value::Integer(n) => Some(n.to_string()),
        Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance => None,
        other => Some(format!("{:?}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortStatus, TransportProtocol};

    fn udp_port(port: u16, status: PortStatus, service: Option<&str>) -> PortResult {
        PortResult {
            port,
            status,
            protocol: TransportProtocol::Udp,
            service: service.map(|s| s.to_string()),
            banner: None,
            confidence: None,
            confidence_source: None,
            cpe: Vec::new(),
        }
    }

    #[test]
    fn recognizes_port_161_regardless_of_service_label() {
        assert!(looks_like_snmp(&udp_port(161, PortStatus::Open, None)));
    }

    #[test]
    fn recognizes_snmp_by_service_name_on_nonstandard_port() {
        assert!(looks_like_snmp(&udp_port(1161, PortStatus::Open, Some("snmp-trap"))));
    }

    #[test]
    fn does_not_flag_unrelated_service_as_snmp() {
        assert!(!looks_like_snmp(&udp_port(53, PortStatus::Open, Some("dns"))));
    }

    #[test]
    fn format_value_extracts_octet_string_trimmed() {
        let v = Value::OctetString(b"router.example.com\0");
        assert_eq!(format_value(&v), Some("router.example.com".to_string()));
    }

    #[test]
    fn format_value_returns_none_for_end_of_walk_markers() {
        assert_eq!(format_value(&Value::EndOfMibView), None);
        assert_eq!(format_value(&Value::NoSuchObject), None);
        assert_eq!(format_value(&Value::NoSuchInstance), None);
    }
}
