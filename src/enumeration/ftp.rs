use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::{Finding, FindingProtocol, HostResult, PortResult, PortStatus, Severity, TransportProtocol};

const MAX_BANNER_LEN: usize = 200;

struct FtpProbeResult {
    banner: Option<String>,
    anonymous_login: bool,
}

fn make_finding(id_suffix: &str, host: IpAddr, port: u16, severity: Severity, evidence: String, recommendation: String) -> Finding {
    Finding {
        id: format!("ftp:{}:{}:{}", id_suffix, host, port),
        host,
        port: Some(port),
        protocol: FindingProtocol::Ftp,
        severity,
        confidence: 100,
        evidence,
        recommendation,
        references: Vec::new(),
        timestamp: Finding::now_ts(),
    }
}

/// Runs FTP enumeration against every open, TCP port on `host` that looks
/// like FTP (port 21, or a service name containing "ftp"): captures the
/// banner and attempts an anonymous login (`USER anonymous` / `PASS ...`).
pub async fn enumerate_host(host: &HostResult, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();

    for port_res in &host.ports {
        if port_res.status != PortStatus::Open || port_res.protocol != TransportProtocol::Tcp {
            continue;
        }
        if !looks_like_ftp(port_res) {
            continue;
        }

        if let Some(result) = probe_ftp(host.ip, port_res.port, timeout_ms).await {
            findings.extend(build_findings(host.ip, port_res.port, result));
        }
    }

    findings
}

fn looks_like_ftp(port_res: &PortResult) -> bool {
    if port_res.port == 21 {
        return true;
    }
    port_res
        .service
        .as_deref()
        .map(|s| s.to_lowercase().contains("ftp"))
        .unwrap_or(false)
}

async fn probe_ftp(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<FtpProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let connect_timeout = Duration::from_millis(timeout_ms);
    let mut stream = timeout(connect_timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

    // The server greets unprompted on connect (220 ...); if nothing comes
    // back at all, this isn't a live FTP control channel worth probing further.
    let banner = read_reply(&mut stream, connect_timeout).await?;

    write_line(&mut stream, "USER anonymous", connect_timeout).await?;
    let user_reply = read_reply(&mut stream, connect_timeout).await;
    let user_code = user_reply.as_deref().and_then(reply_code);

    let anonymous_login = match user_code {
        // Some servers log the "anonymous" user straight in without a password.
        Some(230) => true,
        Some(331) => {
            write_line(&mut stream, "PASS anonymous@netenum.local", connect_timeout).await?;
            let pass_reply = read_reply(&mut stream, connect_timeout).await;
            pass_reply.as_deref().and_then(reply_code) == Some(230)
        }
        _ => false,
    };

    Some(FtpProbeResult {
        banner: Some(banner),
        anonymous_login,
    })
}

fn build_findings(host: IpAddr, port: u16, result: FtpProbeResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(banner) = result.banner.as_deref() {
        let cleaned = clean(banner);
        if !cleaned.is_empty() {
            findings.push(make_finding(
                "banner",
                host,
                port,
                Severity::Info,
                format!("Banner: {}", cleaned),
                String::new(),
            ));
        }
    }

    if result.anonymous_login {
        findings.push(make_finding(
            "anonymous",
            host,
            port,
            Severity::High,
            "FTP server accepted an anonymous login (USER anonymous / PASS ...)".to_string(),
            "Disable anonymous FTP access unless explicitly required; if required, restrict it to a read-only, isolated directory with no write access.".to_string(),
        ));
    }

    findings
}

async fn write_line(stream: &mut TcpStream, line: &str, t: Duration) -> Option<()> {
    let msg = format!("{}\r\n", line);
    timeout(t, stream.write_all(msg.as_bytes())).await.ok()?.ok()?;
    Some(())
}

async fn read_reply(stream: &mut TcpStream, t: Duration) -> Option<String> {
    let mut buf = [0u8; 512];
    let n = timeout(t, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Parses the leading 3-digit FTP reply code (e.g. "230" from
/// "230 Login successful.\r\n"), per RFC 959.
fn reply_code(reply: &str) -> Option<u16> {
    reply.get(0..3)?.parse::<u16>().ok()
}

/// Reduces a raw reply to a single printable line safe for a finding/console:
/// first non-empty line, control characters neutralized, length-capped.
fn clean(raw: &str) -> String {
    let first_line = raw
        .split(['\r', '\n'])
        .find(|l| !l.trim().is_empty())
        .unwrap_or(raw)
        .trim();

    let sanitized: String = first_line.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let sanitized = sanitized.trim();

    if sanitized.chars().count() > MAX_BANNER_LEN {
        let truncated: String = sanitized.chars().take(MAX_BANNER_LEN.saturating_sub(3)).collect();
        format!("{}...", truncated)
    } else {
        sanitized.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortStatus, TransportProtocol};

    fn open_tcp_port(port: u16, service: Option<&str>) -> PortResult {
        PortResult {
            port,
            status: PortStatus::Open,
            protocol: TransportProtocol::Tcp,
            service: service.map(|s| s.to_string()),
            banner: None,
            confidence: None,
            confidence_source: None,
            cpe: Vec::new(),
        }
    }

    #[test]
    fn recognizes_port_21_regardless_of_service_label() {
        assert!(looks_like_ftp(&open_tcp_port(21, None)));
    }

    #[test]
    fn recognizes_ftp_by_service_name_on_nonstandard_port() {
        assert!(looks_like_ftp(&open_tcp_port(2121, Some("ftp-data"))));
    }

    #[test]
    fn does_not_flag_unrelated_service_as_ftp() {
        assert!(!looks_like_ftp(&open_tcp_port(80, Some("http"))));
    }

    #[test]
    fn reply_code_parses_leading_three_digits() {
        assert_eq!(reply_code("230 Login successful.\r\n"), Some(230));
        assert_eq!(reply_code("331 Please specify the password.\r\n"), Some(331));
        assert_eq!(reply_code(""), None);
    }

    #[test]
    fn anonymous_login_finding_has_high_severity_and_recommendation() {
        let host: IpAddr = "10.0.0.5".parse().unwrap();
        let findings = build_findings(
            host,
            21,
            FtpProbeResult {
                banner: Some("220 (vsFTPd 3.0.5)".to_string()),
                anonymous_login: true,
            },
        );
        let anon = findings.iter().find(|f| f.id.starts_with("ftp:anonymous")).expect("anonymous finding must be present");
        assert_eq!(anon.severity, Severity::High);
        assert!(!anon.recommendation.is_empty());
        assert!(findings.iter().any(|f| f.id.starts_with("ftp:banner")));
    }

    #[test]
    fn no_anonymous_finding_when_login_denied() {
        let host: IpAddr = "10.0.0.5".parse().unwrap();
        let findings = build_findings(
            host,
            21,
            FtpProbeResult {
                banner: Some("220 (vsFTPd 3.0.5)".to_string()),
                anonymous_login: false,
            },
        );
        assert!(!findings.iter().any(|f| f.id.starts_with("ftp:anonymous")));
    }
}
