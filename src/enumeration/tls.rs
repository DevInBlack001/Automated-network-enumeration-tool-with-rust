use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::model::{Finding, FindingProtocol, HostResult, PortResult, PortStatus, Severity, TransportProtocol};

/// Accepts any certificate presented -- including self-signed, expired, or
/// hostname-mismatched ones. Enumeration needs to *inspect* whatever
/// certificate a server presents, not validate trust in it.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn make_finding(
    id_suffix: &str,
    host: IpAddr,
    port: u16,
    severity: Severity,
    evidence: String,
    recommendation: String,
) -> Finding {
    Finding {
        id: format!("tls:{}:{}:{}", id_suffix, host, port),
        host,
        port: Some(port),
        protocol: FindingProtocol::Tls,
        severity,
        confidence: 100,
        evidence,
        recommendation,
        references: Vec::new(),
        timestamp: Finding::now_ts(),
    }
}

/// Runs TLS certificate inspection against every open, TCP port on `host`
/// that looks like it speaks TLS (well-known TLS port, or a service name
/// containing "ssl"/"tls"/"https"). Completes a handshake while accepting
/// any certificate presented, then parses the leaf certificate for issuer,
/// SAN, and expiry.
///
/// `sni_hint`, when the target was originally given as a hostname, is the
/// hostname that resolved to this IP -- sent as the TLS SNI value. Without
/// it, a handshake carries no SNI at all, which many shared TLS front-ends
/// (Cloudflare among them) hard-reject even before presenting a certificate.
pub async fn enumerate_host(host: &HostResult, timeout_ms: u64, sni_hint: Option<&str>) -> Vec<Finding> {
    let mut findings = Vec::new();

    for port_res in &host.ports {
        if port_res.status != PortStatus::Open || port_res.protocol != TransportProtocol::Tcp {
            continue;
        }
        if !looks_like_tls(port_res) {
            continue;
        }

        if let Ok(Some(der)) = fetch_cert(host.ip, port_res.port, timeout_ms, sni_hint).await {
            findings.extend(inspect_cert(host.ip, port_res.port, &der));
        }
    }

    findings
}

fn looks_like_tls(port_res: &PortResult) -> bool {
    if matches!(port_res.port, 443 | 8443 | 993 | 995 | 465 | 636 | 8883) {
        return true;
    }
    port_res
        .service
        .as_deref()
        .map(|s| {
            let s = s.to_lowercase();
            s.contains("ssl") || s.contains("tls") || s.contains("https")
        })
        .unwrap_or(false)
}

async fn fetch_cert(ip: IpAddr, port: u16, timeout_ms: u64, sni_hint: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    let addr = SocketAddr::new(ip, port);
    let connect_timeout = Duration::from_millis(timeout_ms);

    let tcp_stream = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    // Prefer the real hostname as SNI when we have one -- many shared TLS
    // front-ends reject a handshake with no SNI before ever presenting a
    // certificate. Fall back to the bare IP (still valid for a rustls
    // ServerName, and fine here since certificate validation is disabled
    // entirely; we only want to see what the server presents).
    let server_name = match sni_hint.and_then(|h| ServerName::try_from(h.to_string()).ok()) {
        Some(name) => name,
        None => ServerName::IpAddress(ip.into()),
    };

    let tls_stream = timeout(connect_timeout, connector.connect(server_name, tcp_stream))
        .await
        .map_err(|_| "TLS handshake timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let leaf = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec());

    Ok(leaf)
}

fn inspect_cert(host: IpAddr, port: u16, der: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let cert = match X509Certificate::from_der(der) {
        Ok((_, cert)) => cert,
        Err(_) => return findings,
    };

    findings.push(make_finding(
        "issuer",
        host,
        port,
        Severity::Info,
        format!("Issuer: {}", cert.issuer()),
        String::new(),
    ));

    findings.push(make_finding(
        "subject",
        host,
        port,
        Severity::Info,
        format!("Subject: {}", cert.subject()),
        String::new(),
    ));

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let names: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(dns) => Some(dns.to_string()),
                _ => None,
            })
            .collect();
        if !names.is_empty() {
            findings.push(make_finding(
                "san",
                host,
                port,
                Severity::Info,
                format!("SAN: {}", names.join(", ")),
                String::new(),
            ));
        }
    }

    let not_after = cert.validity().not_after;
    let now = ASN1Time::now();
    if not_after < now {
        findings.push(make_finding(
            "expired",
            host,
            port,
            Severity::High,
            format!("Certificate expired on {}", not_after),
            "Renew the TLS certificate immediately -- clients may already be rejecting connections."
                .to_string(),
        ));
    } else if let Some(remaining) = not_after - now {
        let days_left = remaining.whole_days();
        if days_left <= 30 {
            findings.push(make_finding(
                "expiring_soon",
                host,
                port,
                Severity::Medium,
                format!("Certificate expires on {} ({} day(s) remaining)", not_after, days_left),
                "Renew the TLS certificate before it expires.".to_string(),
            ));
        } else {
            findings.push(make_finding(
                "validity",
                host,
                port,
                Severity::Info,
                format!("Certificate valid until {}", not_after),
                String::new(),
            ));
        }
    }

    findings
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
    fn recognizes_well_known_tls_ports_regardless_of_service_label() {
        assert!(looks_like_tls(&open_tcp_port(443, None)));
        assert!(looks_like_tls(&open_tcp_port(8443, Some("unknown"))));
    }

    #[test]
    fn recognizes_tls_by_service_name_on_nonstandard_port() {
        assert!(looks_like_tls(&open_tcp_port(9443, Some("https-alt"))));
    }

    #[test]
    fn does_not_flag_plain_http_as_tls() {
        assert!(!looks_like_tls(&open_tcp_port(80, Some("http"))));
    }
}
