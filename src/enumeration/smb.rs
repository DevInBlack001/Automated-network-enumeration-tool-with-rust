use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use smb::{Client, ClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::{Finding, FindingProtocol, HostResult, PortResult, PortStatus, Severity, TransportProtocol};

fn make_finding(
    id_suffix: &str,
    host: IpAddr,
    port: u16,
    severity: Severity,
    evidence: String,
    recommendation: String,
) -> Finding {
    Finding {
        id: format!("smb:{}:{}:{}", id_suffix, host, port),
        host,
        port: Some(port),
        protocol: FindingProtocol::Smb,
        severity,
        confidence: 100,
        evidence,
        recommendation,
        references: Vec::new(),
        timestamp: Finding::now_ts(),
    }
}

/// Runs SMB enumeration against every open TCP port on `host` that looks
/// like SMB (445/139, or a matching service name): dialect + signing
/// requirement (raw SMB2 NEGOTIATE, unauthenticated), SMBv1 exposure (raw
/// legacy negotiate), and a null/anonymous session + share listing check.
pub async fn enumerate_host(host: &HostResult, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();

    for port_res in &host.ports {
        if port_res.status != PortStatus::Open || port_res.protocol != TransportProtocol::Tcp {
            continue;
        }
        if !looks_like_smb(port_res) {
            continue;
        }

        findings.extend(probe_negotiate(host.ip, port_res.port, timeout_ms).await);
        findings.extend(probe_smb1(host.ip, port_res.port, timeout_ms).await);
        findings.extend(probe_null_session_and_shares(host.ip, port_res.port, timeout_ms).await);
    }

    findings
}

fn looks_like_smb(port_res: &PortResult) -> bool {
    if matches!(port_res.port, 445 | 139) {
        return true;
    }
    port_res
        .service
        .as_deref()
        .map(|s| {
            let s = s.to_lowercase();
            s.contains("smb") || s.contains("microsoft-ds") || s.contains("netbios")
        })
        .unwrap_or(false)
}

/// Wraps `payload` in the 4-byte NetBIOS Session Service length prefix all
/// SMB-over-TCP/445 traffic uses (even though it isn't really NetBIOS),
/// sends it, then reads back one full NBSS-framed response.
async fn nbss_request(stream: &mut TcpStream, payload: &[u8], t: Duration) -> Option<Vec<u8>> {
    let len = payload.len() as u32;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.push(0);
    framed.push(((len >> 16) & 0xFF) as u8);
    framed.push(((len >> 8) & 0xFF) as u8);
    framed.push((len & 0xFF) as u8);
    framed.extend_from_slice(payload);

    timeout(t, stream.write_all(&framed)).await.ok()?.ok()?;

    let mut len_buf = [0u8; 4];
    timeout(t, stream.read_exact(&mut len_buf)).await.ok()?.ok()?;
    let resp_len = ((len_buf[1] as usize) << 16) | ((len_buf[2] as usize) << 8) | (len_buf[3] as usize);
    if resp_len == 0 || resp_len > 1 << 20 {
        return None;
    }
    let mut resp = vec![0u8; resp_len];
    timeout(t, stream.read_exact(&mut resp)).await.ok()?.ok()?;
    Some(resp)
}

/// Builds a bare SMB2 NEGOTIATE request (MS-SMB2 2.2.3) offering dialects
/// 2.0.2 through 3.0.2 -- deliberately not 3.1.1, which requires an
/// additional negotiate-context list this probe doesn't need to bother with;
/// a 3.1.1-capable server will still negotiate down to 3.0.2 against this,
/// which is enough to answer "what's the highest legacy-compatible dialect
/// and is signing required".
fn build_smb2_negotiate_request() -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
    header[4..6].copy_from_slice(&64u16.to_le_bytes());
    header[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditRequest

    let dialects: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
    let mut body = vec![0u8; 36];
    body[0..2].copy_from_slice(&36u16.to_le_bytes()); // StructureSize
    body[2..4].copy_from_slice(&(dialects.len() as u16).to_le_bytes()); // DialectCount
    body[4..6].copy_from_slice(&1u16.to_le_bytes()); // SecurityMode: SIGNING_ENABLED

    for d in dialects.iter() {
        body.extend_from_slice(&d.to_le_bytes());
    }

    let mut request = header;
    request.extend_from_slice(&body);
    request
}

fn dialect_to_string(d: u16) -> String {
    match d {
        0x0202 => "SMB 2.0.2".to_string(),
        0x0210 => "SMB 2.1".to_string(),
        0x0222 => "SMB 2.2.2 (pre-release)".to_string(),
        0x0300 => "SMB 3.0".to_string(),
        0x0302 => "SMB 3.0.2".to_string(),
        0x0311 => "SMB 3.1.1".to_string(),
        other => format!("unknown (0x{:04x})", other),
    }
}

async fn probe_negotiate(ip: IpAddr, port: u16, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let t = Duration::from_millis(timeout_ms);
    let addr = SocketAddr::new(ip, port);

    let Ok(Ok(mut stream)) = timeout(t, TcpStream::connect(addr)).await else {
        return findings;
    };

    let request = build_smb2_negotiate_request();
    let Some(response) = nbss_request(&mut stream, &request, t).await else {
        return findings;
    };

    // NEGOTIATE response body starts right after the 64-byte SMB2 header;
    // SecurityMode is at body+2, DialectRevision at body+4 (MS-SMB2 2.2.4).
    if response.len() < 70 || response[0..4] != [0xFE, b'S', b'M', b'B'] {
        return findings;
    }

    let security_mode = u16::from_le_bytes([response[66], response[67]]);
    let dialect = u16::from_le_bytes([response[68], response[69]]);

    findings.push(make_finding(
        "dialect",
        ip,
        port,
        Severity::Info,
        format!("Negotiated SMB dialect: {}", dialect_to_string(dialect)),
        String::new(),
    ));

    let signing_required = security_mode & 0x0002 != 0;
    if signing_required {
        findings.push(make_finding(
            "signing",
            ip,
            port,
            Severity::Info,
            "SMB message signing is required".to_string(),
            String::new(),
        ));
    } else {
        findings.push(make_finding(
            "signing",
            ip,
            port,
            Severity::Medium,
            format!(
                "SMB message signing is not required (security mode: {:#06x})",
                security_mode
            ),
            "Require SMB message signing on this server to mitigate SMB relay attacks.".to_string(),
        ));
    }

    findings
}

/// Builds a legacy SMB1 SMB_COM_NEGOTIATE request (MS-CIFS 2.2.4.52)
/// offering only the "NT LM 0.12" dialect. A server that still speaks SMB1
/// answers with an SMB1-framed response (0xFF 'SMB'); one with SMB1
/// disabled resets the connection, times out, or answers with an SMB2 error.
fn build_smb1_negotiate_request() -> Vec<u8> {
    let mut header = vec![0u8; 32];
    header[0..4].copy_from_slice(&[0xFF, b'S', b'M', b'B']);
    header[4] = 0x72; // SMB_COM_NEGOTIATE
    header[9] = 0x18; // Flags
    header[10..12].copy_from_slice(&0xC843u16.to_le_bytes()); // Flags2
    header[24..26].copy_from_slice(&0xFFFFu16.to_le_bytes()); // TID (none yet)

    let dialect = b"NT LM 0.12\0";
    let mut body = Vec::new();
    body.push(0u8); // WordCount
    let byte_count = 1 + dialect.len();
    body.extend_from_slice(&(byte_count as u16).to_le_bytes());
    body.push(0x02); // Buffer format: Dialect
    body.extend_from_slice(dialect);

    let mut request = header;
    request.extend_from_slice(&body);
    request
}

async fn probe_smb1(ip: IpAddr, port: u16, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let t = Duration::from_millis(timeout_ms);
    let addr = SocketAddr::new(ip, port);

    let Ok(Ok(mut stream)) = timeout(t, TcpStream::connect(addr)).await else {
        return findings;
    };

    let request = build_smb1_negotiate_request();
    let Some(response) = nbss_request(&mut stream, &request, t).await else {
        return findings;
    };

    if response.len() >= 4 && response[0..4] == [0xFF, b'S', b'M', b'B'] {
        findings.push(make_finding(
            "smbv1",
            ip,
            port,
            Severity::High,
            "Server responded to a legacy SMBv1 negotiate request".to_string(),
            "Disable the SMBv1 protocol entirely -- it lacks modern security protections and is deprecated. On Windows: `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`; on Samba: set `server min protocol = SMB2_10` (or higher) in smb.conf.".to_string(),
        ));
    }

    findings
}

async fn probe_null_session_and_shares(ip: IpAddr, port: u16, timeout_ms: u64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let t = Duration::from_millis(timeout_ms);
    let server = ip.to_string();

    let mut config = ClientConfig::default();
    config.connection.port = Some(port);
    // Skip the legacy SMB1-then-upgrade negotiation dance and go straight to
    // SMB2 -- this probe already confirmed dialect/signing via its own bare
    // SMB2 NEGOTIATE in `probe_negotiate`, so there's nothing to gain from
    // the multi-protocol handshake here, and it's a common source of
    // interop issues against servers that don't implement the SMB2 wildcard
    // dialect upgrade exactly as this crate expects.
    config.connection.smb2_only_negotiate = true;
    // A guest/anonymous session is inherently unauthenticated, so it has no
    // signing key to sign with -- without this, the client errors out
    // whenever the server marks such a session as requiring signing, even
    // though "requires signing on a guest session" is itself part of what
    // this check is trying to observe.
    config.connection.allow_unsigned_guest_access = true;
    let client = Client::new(config);

    // A fully empty username+password pair isn't valid NTLM input to this
    // client's SSPI layer (it rejects it as an empty identity before ever
    // reaching the network) -- "guest" with no password is the standard
    // stand-in for an unauthenticated/null-session attempt.
    let ipc_result = timeout(t, client.ipc_connect(&server, "guest", String::new())).await;
    let null_session_ok = matches!(ipc_result, Ok(Ok(())));

    if !null_session_ok {
        return findings;
    }

    findings.push(make_finding(
        "null_session",
        ip,
        port,
        Severity::High,
        "SMB server accepted a session with no real credentials ('guest' account, empty password)".to_string(),
        "Disable null/anonymous and guest SMB access (RestrictAnonymous on Windows; disable the guest account and restrict anonymous access in Samba's smb.conf).".to_string(),
    ));

    if let Ok(Ok(shares)) = timeout(t, client.list_shares(&server)).await {
        let names: Vec<String> = shares.iter().filter_map(share_name).collect();
        if !names.is_empty() {
            findings.push(make_finding(
                "shares",
                ip,
                port,
                Severity::High,
                format!("Shares enumerable via null session: {}", names.join(", ")),
                "Restrict share access to authenticated, authorized users; disable null-session enumeration.".to_string(),
            ));
        }
    }

    findings
}

fn share_name(info: &smb_rpc::interface::ShareInfo1) -> Option<String> {
    info.netname.as_ref().map(|n| n.to_string())
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

    #[tokio::test]
    #[ignore]
    async fn manual_probe_negotiate_against_fixture() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let findings = probe_negotiate(ip, 4450, 3000).await;
        eprintln!("negotiate findings: {:#?}", findings);
        assert!(!findings.is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn manual_probe_smb1_against_fixture() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let findings = probe_smb1(ip, 4450, 3000).await;
        eprintln!("smb1 findings: {:#?}", findings);
    }

    #[tokio::test]
    #[ignore]
    async fn manual_probe_null_session_against_fixture() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let findings = probe_null_session_and_shares(ip, 4450, 5000).await;
        eprintln!("null session findings: {:#?}", findings);
        assert!(!findings.is_empty());
    }

    #[test]
    fn recognizes_port_445_and_139_regardless_of_service_label() {
        assert!(looks_like_smb(&open_tcp_port(445, None)));
        assert!(looks_like_smb(&open_tcp_port(139, None)));
    }

    #[test]
    fn recognizes_smb_by_service_name_on_nonstandard_port() {
        assert!(looks_like_smb(&open_tcp_port(4450, Some("microsoft-ds"))));
    }

    #[test]
    fn does_not_flag_unrelated_service_as_smb() {
        assert!(!looks_like_smb(&open_tcp_port(80, Some("http"))));
    }

    #[test]
    fn dialect_to_string_maps_known_values() {
        assert_eq!(dialect_to_string(0x0202), "SMB 2.0.2");
        assert_eq!(dialect_to_string(0x0311), "SMB 3.1.1");
        assert!(dialect_to_string(0x9999).contains("unknown"));
    }

    #[test]
    fn smb2_negotiate_request_has_correct_header_signature_and_length() {
        let req = build_smb2_negotiate_request();
        assert_eq!(&req[0..4], &[0xFE, b'S', b'M', b'B']);
        assert_eq!(req.len(), 64 + 36 + 4 * 2);
    }

    #[test]
    fn smb1_negotiate_request_has_correct_header_signature() {
        let req = build_smb1_negotiate_request();
        assert_eq!(&req[0..4], &[0xFF, b'S', b'M', b'B']);
        assert_eq!(req[4], 0x72);
    }
}
