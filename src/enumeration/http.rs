use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::{Finding, FindingProtocol, HostResult, PortStatus, Severity, TransportProtocol};

/// Response headers known to leak backend technology when present, worth
/// surfacing individually as tech-stack fingerprinting signals.
const TECH_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "via",
];

struct HttpResponse {
    headers: HashMap<String, String>,
    body: String,
}

fn make_finding(id_suffix: &str, host: IpAddr, port: u16, evidence: String) -> Finding {
    Finding {
        id: format!("http:{}:{}:{}", id_suffix, host, port),
        host,
        port: Some(port),
        protocol: FindingProtocol::Http,
        severity: Severity::Info,
        confidence: 100,
        evidence,
        recommendation: String::new(),
        references: Vec::new(),
        timestamp: Finding::now_ts(),
    }
}

/// Runs HTTP fingerprinting against every open, TCP, HTTP-identified port on
/// `host`: fetches `/` fresh (independent of the truncated single-line banner
/// already captured), then extracts the page title and any response headers
/// that reveal backend technology.
pub async fn enumerate_host(host: &HostResult, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();

    for port_res in &host.ports {
        if port_res.status != PortStatus::Open || port_res.protocol != TransportProtocol::Tcp {
            continue;
        }
        let is_http = port_res
            .service
            .as_deref()
            .map(|s| s.to_lowercase().contains("http"))
            .unwrap_or(false);
        if !is_http {
            continue;
        }

        if let Some(resp) = fetch(host.ip, port_res.port, timeout_ms).await {
            for name in TECH_HEADERS {
                if let Some(value) = resp.headers.get(*name) {
                    findings.push(make_finding(
                        &format!("header:{}", name),
                        host.ip,
                        port_res.port,
                        format!("{}: {}", name, value),
                    ));
                }
            }

            if let Some(title) = extract_title(&resp.body) {
                findings.push(make_finding(
                    "title",
                    host.ip,
                    port_res.port,
                    format!("Title: {}", title),
                ));
            }
        }
    }

    findings
}

async fn fetch(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<HttpResponse> {
    let addr = SocketAddr::new(ip, port);
    let connect_timeout = Duration::from_millis(timeout_ms);
    let mut stream = timeout(connect_timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

    let request = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: netenum/0.1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        ip
    );
    timeout(connect_timeout, stream.write_all(request.as_bytes())).await.ok()?.ok()?;

    let mut raw = Vec::new();
    let _ = timeout(connect_timeout, stream.read_to_end(&mut raw)).await;
    if raw.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&raw).into_owned();

    let mut parts = text.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    if !status_line.starts_with("HTTP/") {
        return None;
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }

    Some(HttpResponse { headers, body })
}

/// Extracts the contents of the first `<title>` tag from an HTML body, if any.
fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start_tag = lower.find("<title")?;
    let after_open = lower[start_tag..].find('>')? + start_tag + 1;
    let end_tag = lower[after_open..].find("</title")? + after_open;
    let title = body.get(after_open..end_tag)?.trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_title() {
        let body = "<html><head><TiTlE>  Example Domain  </TiTlE></head><body></body></html>";
        assert_eq!(extract_title(body), Some("Example Domain".to_string()));
    }

    #[test]
    fn returns_none_when_no_title_tag() {
        let body = "<html><body>No title here</body></html>";
        assert_eq!(extract_title(body), None);
    }

    #[test]
    fn returns_none_for_empty_title() {
        let body = "<html><head><title>   </title></head></html>";
        assert_eq!(extract_title(body), None);
    }

    #[test]
    fn finding_ids_are_scoped_per_header_name() {
        let host: IpAddr = "10.0.0.5".parse().unwrap();
        let a = make_finding("header:server", host, 80, "Server: nginx".to_string());
        let b = make_finding("header:x-powered-by", host, 80, "X-Powered-By: PHP/8.2".to_string());
        assert_ne!(a.id, b.id);
        assert_eq!(a.protocol, FindingProtocol::Http);
        assert_eq!(a.severity, Severity::Info);
    }
}