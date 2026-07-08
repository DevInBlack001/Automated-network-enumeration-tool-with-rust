use async_trait::async_trait;
use std::net::{IpAddr, UdpSocket};
use std::time::Duration;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, tcp_packet_iter};
use pnet::packet::ip::IpNextHeaderProtocols;
use crate::model::PortStatus;
use crate::scanners::PortScanner;

pub struct SynScanner;

impl SynScanner {
    pub fn new() -> Self {
        SynScanner
    }
}

// Function to find the source IP used to route to the target IP
fn get_source_ip(target: IpAddr) -> Option<IpAddr> {
    let dest = std::net::SocketAddr::new(target, 9); // discard port
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(dest).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[async_trait]
impl PortScanner for SynScanner {
    fn name(&self) -> &'static str {
        "SYN Scan"
    }

    fn requires_raw_socket(&self) -> bool {
        true
    }

    async fn scan_port(&self, ip: IpAddr, port: u16, timeout: Duration) -> PortStatus {
        let src_ip = match get_source_ip(ip) {
            Some(ip) => ip,
            None => return PortStatus::Filtered,
        };

        // Pick a random/unique ephemeral source port
        let src_port = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s.local_addr().map(|a| a.port()).unwrap_or(54321),
            Err(_) => 54321,
        };

        // Open transport channel
        let protocol = match ip {
            IpAddr::V4(_) => TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
            IpAddr::V6(_) => TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
        };

        // Run the blocking raw socket interactions on spawn_blocking
        let res = tokio::task::spawn_blocking(move || {
            let (mut tx, mut rx) = match transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(_) => return PortStatus::Closed,
            };

            // Craft TCP SYN packet (20 bytes header size)
            let mut buffer = [0u8; 20];
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer).unwrap();
            
            tcp_packet.set_source(src_port);
            tcp_packet.set_destination(port);
            tcp_packet.set_sequence(123456789); // Arbitrary initial sequence number
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5); // 5 * 32 bits = 20 bytes
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(64240);

            // Compute TCP checksum
            match (src_ip, ip) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src, &dst);
                    tcp_packet.set_checksum(checksum);
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    let checksum = pnet::packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src, &dst);
                    tcp_packet.set_checksum(checksum);
                }
                _ => return PortStatus::Filtered,
            }

            // Send packet
            if tx.send_to(tcp_packet.to_immutable(), ip).is_err() {
                return PortStatus::Filtered;
            }

            // Loop to receive matching packet or timeout
            let mut iter = tcp_packet_iter(&mut rx);
            let start_time = std::time::Instant::now();

            loop {
                let elapsed = start_time.elapsed();
                if elapsed >= timeout {
                    break;
                }
                let remaining = timeout - elapsed;

                match iter.next_with_timeout(remaining) {
                    Ok(Some((packet, sender_ip))) => {
                        // Validate packet sender, source port, and destination port
                        if sender_ip == ip && packet.get_source() == port && packet.get_destination() == src_port {
                            let flags = packet.get_flags();
                            
                            // Check if SYN-ACK is set (18) -> Port is open
                            if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
                                // Clean up half-open connection with a RST packet
                                let mut rst_buffer = [0u8; 20];
                                let mut rst_packet = MutableTcpPacket::new(&mut rst_buffer).unwrap();
                                rst_packet.set_source(src_port);
                                rst_packet.set_destination(port);
                                rst_packet.set_sequence(packet.get_acknowledgement());
                                rst_packet.set_acknowledgement(packet.get_sequence() + 1);
                                rst_packet.set_data_offset(5);
                                rst_packet.set_flags(TcpFlags::RST);
                                rst_packet.set_window(0);

                                match (src_ip, ip) {
                                    (IpAddr::V4(src), IpAddr::V4(dst)) => {
                                        let checksum = pnet::packet::tcp::ipv4_checksum(&rst_packet.to_immutable(), &src, &dst);
                                        rst_packet.set_checksum(checksum);
                                    }
                                    (IpAddr::V6(src), IpAddr::V6(dst)) => {
                                        let checksum = pnet::packet::tcp::ipv6_checksum(&rst_packet.to_immutable(), &src, &dst);
                                        rst_packet.set_checksum(checksum);
                                    }
                                    _ => {}
                                }
                                let _ = tx.send_to(rst_packet.to_immutable(), ip);
                                return PortStatus::Open;
                            }
                            
                            // Check if RST is set (4) -> Port is closed
                            if (flags & TcpFlags::RST) != 0 {
                                return PortStatus::Closed;
                            }
                        }
                    }
                    Ok(None) => break, // Timeout reached
                    Err(_) => break,   // Receiver error
                }
            }

            PortStatus::Filtered
        }).await;

        res.unwrap_or(PortStatus::Filtered)
    }
}
