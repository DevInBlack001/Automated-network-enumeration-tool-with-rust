use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::{HostStatus, PortStatus, ScanResultSummary, ServiceSource, TransportProtocol};

const MAX_BANNER_LEN: usize = 100;
const IMMEDIATE_READ_TIMEOUT_MS: u64 = 600;

/// Attempts to capture a service banner from every open TCP port that doesn't
/// already have one, without relying on Nmap or a port-specific Lua plugin.
///
/// Most services either banner unprompted on connect (SSH, FTP, SMTP, POP3,
/// IMAP...) or respond to a generic HTTP/1.0 request (the overwhelming majority
/// of silent TCP services encountered in practice); anything else is left blank
/// for Nmap or a custom plugin to fill in later.
pub async fn grab_banners(results: &mut ScanResultSummary, timeout_ms: u64) {
    let connect_timeout = Duration::from_millis(timeout_ms);

    for host in &mut results.hosts {
        if host.status != HostStatus::Up {
            continue;
        }
        for port_res in &mut host.ports {
            if port_res.status != PortStatus::Open
                || port_res.protocol != TransportProtocol::Tcp
                || port_res.banner.is_some()
            {
                continue;
            }

            if let Some(banner) = grab_one(host.ip, port_res.port, connect_timeout).await {
                if port_res.service.is_none() {
                    if let Some((name, confidence)) = identify_banner(&banner) {
                        port_res.service = Some(name.to_string());
                        port_res.confidence = Some(confidence);
                        port_res.confidence_source = Some(ServiceSource::NativeBanner);
                    }
                    // No match: leave `service` unset rather than fabricate a
                    // port-number-based guess. The raw banner is still saved below
                    // for a human (or Nmap/a plugin) to make sense of.
                }
                port_res.banner = Some(banner);
            }
        }
    }
}

/// Identifies a service directly from the content it sent back — real signature
/// matching against standardized, unambiguous protocol banner formats, entirely
/// independent of which port it came from. Genuinely ambiguous responses (e.g. a
/// bare "220" greeting, used by both FTP and SMTP) are deliberately left
/// unmatched rather than guessed.
fn identify_banner(banner: &str) -> Option<(&'static str, u8)> {
    if banner.starts_with("SSH-") {
        return Some(("ssh", 90));
    }
    if banner.starts_with("HTTP/") {
        // Especially strong signal here: our own probe was an HTTP GET, so this
        // is a confirmed protocol round-trip, not just a passive banner match.
        return Some(("http", 85));
    }
    if banner.starts_with("RFB 0") {
        return Some(("vnc", 90));
    }
    if banner.starts_with("+OK") {
        return Some(("pop3", 80));
    }
    if banner.starts_with("* OK") || banner.starts_with("* PREAUTH") {
        return Some(("imap", 80));
    }
    if banner.starts_with("220") {
        let upper = banner.to_uppercase();
        if upper.contains("FTP") {
            return Some(("ftp", 80));
        }
        if upper.contains("SMTP") {
            return Some(("smtp", 80));
        }
    }
    None
}

async fn grab_one(ip: IpAddr, port: u16, connect_timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(connect_timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

    // 1. Many services (SSH, FTP, SMTP, POP3, IMAP...) banner immediately on connect.
    let immediate_timeout = Duration::from_millis(IMMEDIATE_READ_TIMEOUT_MS);
    if let Some(raw) = read_some(&mut stream, immediate_timeout).await {
        return Some(clean_banner(&raw));
    }

    // 2. Otherwise, try a generic HTTP/1.0 request as a catch-all probe: the
    // overwhelming majority of silent TCP services encountered in the wild are
    // HTTP or HTTP-ish, and genuinely unrelated services will simply not
    // respond usefully to it.
    let request = format!("GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", ip);
    timeout(connect_timeout, stream.write_all(request.as_bytes())).await.ok()?.ok()?;

    let raw = read_some(&mut stream, connect_timeout).await?;
    Some(clean_banner(&raw))
}

async fn read_some(stream: &mut TcpStream, read_timeout: Duration) -> Option<String> {
    let mut buf = [0u8; 512];
    let n = timeout(read_timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Reduces a raw response to a single printable line safe for a stdout table:
/// picks the first non-empty line, then neutralizes control characters (e.g.
/// ANSI escapes a hostile service could otherwise inject into the terminal).
fn clean_banner(raw: &str) -> String {
    let first_line = raw
        .split(['\r', '\n'])
        .find(|l| !l.trim().is_empty())
        .unwrap_or(raw)
        .trim();

    let sanitized: String = first_line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let sanitized = sanitized.trim();

    if sanitized.chars().count() > MAX_BANNER_LEN {
        let truncated: String = sanitized.chars().take(MAX_BANNER_LEN.saturating_sub(3)).collect();
        format!("{}...", truncated)
    } else {
        sanitized.to_string()
    }
}
