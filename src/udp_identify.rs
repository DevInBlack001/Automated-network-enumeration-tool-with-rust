use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::model::{HostStatus, PortStatus, ScanResultSummary, ServiceSource, TransportProtocol};
use crate::scanners::udp::{DNS_QUERY, NTP_REQUEST, SNMP_GET_SYSDESCR};

/// Re-probes each open/ambiguous UDP port with real protocol-specific requests
/// (the same ones used during scanning) and validates the *structure* of the
/// response to confirm the service's actual identity, not just "something
/// answered". Every protocol is tried regardless of port number, exactly like
/// the TCP banner signature matching in `banner.rs`.
pub async fn identify_services(results: &mut ScanResultSummary, timeout_ms: u64) {
    let probe_timeout = Duration::from_millis(timeout_ms);

    for host in &mut results.hosts {
        if host.status != HostStatus::Up {
            continue;
        }
        for port_res in &mut host.ports {
            if port_res.protocol != TransportProtocol::Udp
                || !matches!(port_res.status, PortStatus::Open | PortStatus::OpenFiltered)
                || port_res.service.is_some()
            {
                continue;
            }

            if let Some((name, confidence)) = identify_one(host.ip, port_res.port, probe_timeout).await {
                port_res.service = Some(name.to_string());
                port_res.confidence = Some(confidence);
                port_res.confidence_source = Some(ServiceSource::NativeBanner);
            }
        }
    }
}

async fn identify_one(ip: IpAddr, port: u16, probe_timeout: Duration) -> Option<(&'static str, u8)> {
    if let Some(r) = probe_dns(ip, port, probe_timeout).await {
        return Some(r);
    }
    if let Some(r) = probe_ntp(ip, port, probe_timeout).await {
        return Some(r);
    }
    if let Some(r) = probe_snmp(ip, port, probe_timeout).await {
        return Some(r);
    }
    None
}

async fn send_recv(ip: IpAddr, port: u16, payload: &[u8], probe_timeout: Duration) -> Option<Vec<u8>> {
    let bind_addr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr).await.ok()?;
    socket.connect(SocketAddr::new(ip, port)).await.ok()?;
    socket.send(payload).await.ok()?;

    let mut buf = [0u8; 512];
    let n = timeout(probe_timeout, socket.recv(&mut buf)).await.ok()?.ok()?;
    Some(buf[..n].to_vec())
}

/// A real DNS response must echo our transaction ID back and have the QR
/// (response) bit set in the flags byte -- not just any bytes on port 53.
async fn probe_dns(ip: IpAddr, port: u16, probe_timeout: Duration) -> Option<(&'static str, u8)> {
    let resp = send_recv(ip, port, &DNS_QUERY, probe_timeout).await?;
    let echoes_txn_id = resp.len() >= 3 && resp[0] == DNS_QUERY[0] && resp[1] == DNS_QUERY[1];
    let is_response = resp.len() >= 3 && (resp[2] & 0x80) != 0;
    if echoes_txn_id && is_response {
        return Some(("dns", 90));
    }
    None
}

/// A real NTP response must be full-length and report Mode 4 (server), matching
/// our Mode 3 (client) request.
async fn probe_ntp(ip: IpAddr, port: u16, probe_timeout: Duration) -> Option<(&'static str, u8)> {
    let resp = send_recv(ip, port, &NTP_REQUEST, probe_timeout).await?;
    if resp.len() >= 48 && (resp[0] & 0x07) == 4 {
        return Some(("ntp", 85));
    }
    None
}

/// A real SNMP response must be a BER SEQUENCE containing a GetResponse-PDU
/// (context tag 0xA2) and must echo our "public" community string back.
async fn probe_snmp(ip: IpAddr, port: u16, probe_timeout: Duration) -> Option<(&'static str, u8)> {
    let resp = send_recv(ip, port, &SNMP_GET_SYSDESCR, probe_timeout).await?;
    let is_sequence = resp.first() == Some(&0x30);
    let has_get_response_pdu = resp.contains(&0xA2);
    let echoes_community = resp.windows(6).any(|w| w == b"public");
    if is_sequence && has_get_response_pdu && echoes_community {
        return Some(("snmp", 80));
    }
    None
}
