use std::net::IpAddr;
use std::str::FromStr;

use futures::StreamExt;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::rr::{Name, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_resolver::TokioResolver;

use crate::model::{Finding, FindingProtocol, Severity};

/// Ensures `domain` is a fully-qualified name (trailing dot) so the resolver
/// doesn't append resolv.conf search-domain suffixes during lookup.
fn fqdn(domain: &str) -> String {
    if domain.ends_with('.') {
        domain.to_string()
    } else {
        format!("{}.", domain)
    }
}

fn record_finding(kind: &str, domain: &str, host: IpAddr, data: impl std::fmt::Display) -> Finding {
    Finding {
        id: format!("dns:{}:{}:{}", kind, domain, data),
        host,
        port: Some(53),
        protocol: FindingProtocol::Dns,
        severity: Severity::Info,
        confidence: 100,
        evidence: format!("{} {} {}", domain, kind.to_uppercase(), data),
        recommendation: String::new(),
        references: Vec::new(),
        timestamp: Finding::now_ts(),
    }
}

/// Runs DNS enumeration against `domain`: collects standard records (A/AAAA,
/// CNAME, NS, MX, TXT), attempts a reverse lookup on the primary resolved IP,
/// and probes each authoritative nameserver for an unauthenticated zone
/// transfer (AXFR).
///
/// Returns the collected findings plus the primary IP they're anchored to
/// (the first A/AAAA record), so the caller can correlate this against the
/// corresponding scanned host.
pub async fn enumerate(domain: &str) -> Result<(IpAddr, Vec<Finding>), String> {
    let fqdn_name = fqdn(domain);
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| format!("Failed to build DNS resolver: {}", e))?
        .build();

    let ip_lookup = resolver
        .lookup_ip(fqdn_name.as_str())
        .await
        .map_err(|e| format!("Failed to resolve '{}': {}", domain, e))?;

    let primary_ip = ip_lookup
        .iter()
        .next()
        .ok_or_else(|| format!("No A/AAAA records found for '{}'", domain))?;

    let mut findings = Vec::new();

    for ip in ip_lookup.iter() {
        findings.push(record_finding("a", domain, primary_ip, ip));
    }

    if let Ok(cname) = resolver.lookup(fqdn_name.as_str(), RecordType::CNAME).await {
        for rdata in cname.iter() {
            findings.push(record_finding("cname", domain, primary_ip, rdata));
        }
    }

    let mut nameservers: Vec<String> = Vec::new();
    if let Ok(ns) = resolver.ns_lookup(fqdn_name.as_str()).await {
        for name in ns.iter() {
            nameservers.push(name.to_string());
            findings.push(record_finding("ns", domain, primary_ip, name));
        }
    }

    if let Ok(mx) = resolver.mx_lookup(fqdn_name.as_str()).await {
        for record in mx.iter() {
            findings.push(record_finding("mx", domain, primary_ip, record));
        }
    }

    if let Ok(txt) = resolver.txt_lookup(fqdn_name.as_str()).await {
        for record in txt.iter() {
            findings.push(record_finding("txt", domain, primary_ip, record));
        }
    }

    if let Ok(reverse) = resolver.reverse_lookup(primary_ip).await {
        for name in reverse.iter() {
            findings.push(record_finding("ptr", domain, primary_ip, name));
        }
    }

    for ns_host in &nameservers {
        match try_axfr(&fqdn_name, ns_host).await {
            Ok(Some(record_count)) => {
                findings.push(Finding {
                    id: format!("dns:axfr:{}:{}", domain, ns_host),
                    host: primary_ip,
                    port: Some(53),
                    protocol: FindingProtocol::Dns,
                    severity: Severity::High,
                    confidence: 100,
                    evidence: format!(
                        "Zone transfer (AXFR) for '{}' succeeded against nameserver '{}', {} record(s) returned",
                        domain, ns_host, record_count
                    ),
                    recommendation:
                        "Restrict zone transfers to authorized secondary nameservers only (e.g. `allow-transfer` in BIND, equivalent ACLs elsewhere)."
                            .to_string(),
                    references: vec!["CWE-200".to_string()],
                    timestamp: Finding::now_ts(),
                });
            }
            Ok(None) => {
                // Refused/empty transfer is the secure, expected outcome — no finding needed.
            }
            Err(_) => {
                // Nameserver unreachable on TCP/53 or connection-level failure; not conclusive
                // either way, so no finding is recorded.
            }
        }
    }

    Ok((primary_ip, findings))
}

/// Attempts an AXFR zone transfer for `zone` against `ns_host` (a DNS name
/// from an NS record). Returns `Ok(Some(count))` with the number of records
/// transferred if the server allowed it, `Ok(None)` if refused/empty, or
/// `Err` if the nameserver couldn't be reached at all.
async fn try_axfr(zone: &str, ns_host: &str) -> Result<Option<usize>, String> {
    let ns_ip = tokio::net::lookup_host(format!("{}:53", ns_host.trim_end_matches('.')))
        .await
        .map_err(|e| format!("Failed to resolve nameserver '{}': {}", ns_host, e))?
        .next()
        .ok_or_else(|| format!("Nameserver '{}' resolved to no addresses", ns_host))?;

    let zone_name = Name::from_str(zone).map_err(|e| format!("Invalid zone name '{}': {}", zone, e))?;

    let (stream, sender) = TcpClientStream::new(ns_ip, None, None, TokioRuntimeProvider::new());
    let (mut client, bg) = Client::new(stream, sender, None)
        .await
        .map_err(|e| format!("Connection to '{}' failed: {}", ns_host, e))?;
    tokio::spawn(bg);

    let mut xfr = client.zone_transfer(zone_name, None);
    let mut total_records = 0usize;
    let mut got_any_response = false;

    while let Some(result) = xfr.next().await {
        match result {
            Ok(response) => {
                got_any_response = true;
                total_records += response.answers().len();
            }
            Err(_) => break,
        }
    }

    if !got_any_response || total_records == 0 {
        Ok(None)
    } else {
        Ok(Some(total_records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_appends_trailing_dot_when_missing() {
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(fqdn("example.com."), "example.com.");
    }

    #[test]
    fn record_finding_ids_are_stable_for_same_input() {
        let host: IpAddr = "10.0.0.5".parse().unwrap();
        let a = record_finding("ns", "example.com", host, "ns1.example.com");
        let b = record_finding("ns", "example.com", host, "ns1.example.com");
        assert_eq!(a.id, b.id);
        assert_eq!(a.id, "dns:ns:example.com:ns1.example.com");
        assert_eq!(a.protocol, FindingProtocol::Dns);
        assert_eq!(a.severity, Severity::Info);
    }
}