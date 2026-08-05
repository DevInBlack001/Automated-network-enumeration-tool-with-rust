use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::{HostStatus, PortStatus, ScanResultSummary, ServiceSource, TransportProtocol};
use crate::services;

const MAX_BANNER_LEN: usize = 100;
const IMMEDIATE_READ_TIMEOUT_MS: u64 = 600;
/// Confidence assigned when a live banner/response was captured but the service
/// name itself is still just the port-number guess (no real signature matching).
const NATIVE_BANNER_CONFIDENCE: u8 = 50;
/// Confidence assigned when the response is a literal HTTP status line: this is
/// direct protocol confirmation (our own probe was an HTTP GET), not a guess.
const HTTP_CONFIRMED_CONFIDENCE: u8 = 65;

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
                    if banner.starts_with("HTTP/") {
                        // Direct protocol confirmation: our own probe was an HTTP GET,
                        // and we got back a real HTTP status line in response.
                        port_res.service = Some("http".to_string());
                        port_res.confidence = Some(HTTP_CONFIRMED_CONFIDENCE);
                        port_res.confidence_source = Some(ServiceSource::NativeBanner);
                    } else {
                        let guess = services::lookup(port_res.protocol, port_res.port);
                        if guess != "unknown" {
                            port_res.service = Some(guess.to_string());
                            port_res.confidence = Some(NATIVE_BANNER_CONFIDENCE);
                            port_res.confidence_source = Some(ServiceSource::NativeBanner);
                        }
                    }
                }
                port_res.banner = Some(banner);
            }
        }
    }
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
