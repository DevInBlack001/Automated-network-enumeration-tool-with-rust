use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::model::{PortStatus, TransportProtocol};
use crate::scanners::PortScanner;

pub struct UdpScanner;

impl UdpScanner {
    pub fn new() -> Self {
        UdpScanner
    }
}

// Standard DNS query for the root NS record (transaction id 0x1234).
pub(crate) const DNS_QUERY: [u8; 17] = [
    0x12, 0x34, // Transaction ID
    0x01, 0x00, // Flags: standard query, recursion desired
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x00, // Root name (.)
    0x00, 0x02, // Type: NS
    0x00, 0x01, // Class: IN
];

// Classic 48-byte NTP client request (LI=0, VN=3, Mode=3 client).
pub(crate) const NTP_REQUEST: [u8; 48] = [
    0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// SNMPv1 GetRequest for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0), community "public".
pub(crate) const SNMP_GET_SYSDESCR: [u8; 40] = [
    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xA0, 0x19, 0x02,
    0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06,
    0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
];

/// Returns a protocol-specific probe payload likely to elicit a response from
/// well-known UDP services; unknown ports fall back to an empty datagram.
fn probe_payload(port: u16) -> &'static [u8] {
    match port {
        53 => &DNS_QUERY,
        123 => &NTP_REQUEST,
        161 => &SNMP_GET_SYSDESCR,
        _ => &[],
    }
}

#[async_trait]
impl PortScanner for UdpScanner {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn requires_raw_socket(&self) -> bool {
        false
    }

    fn protocol(&self) -> TransportProtocol {
        TransportProtocol::Udp
    }

    async fn scan_port(&self, ip: IpAddr, port: u16, timeout_duration: Duration) -> PortStatus {
        let bind_addr = match ip {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };

        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => return PortStatus::Filtered,
        };

        // Connecting a UDP socket sets its default peer. On Linux/BSD this also
        // means a subsequent ICMP "port unreachable" surfaces as ECONNREFUSED
        // on send/recv, letting us detect closed ports without a raw socket.
        if socket.connect((ip, port)).await.is_err() {
            return PortStatus::Filtered;
        }

        if let Err(e) = socket.send(probe_payload(port)).await {
            return if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                PortStatus::Filtered
            };
        }

        let mut buf = [0u8; 512];
        match timeout(timeout_duration, socket.recv(&mut buf)).await {
            Ok(Ok(_)) => PortStatus::Open,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortStatus::Closed,
            Ok(Err(_)) => PortStatus::Filtered,
            Err(_) => PortStatus::OpenFiltered,
        }
    }
}
