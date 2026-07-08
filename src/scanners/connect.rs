use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use crate::model::PortStatus;
use crate::scanners::PortScanner;

pub struct ConnectScanner;

#[async_trait]
impl PortScanner for ConnectScanner {
    fn name(&self) -> &'static str {
        "connect"
    }

    fn requires_raw_socket(&self) -> bool {
        false
    }

    async fn scan_port(&self, ip: IpAddr, port: u16, timeout_duration: Duration) -> PortStatus {
        let addr = SocketAddr::new(ip, port);
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => PortStatus::Open,
            Ok(Err(err)) => {
                match err.kind() {
                    std::io::ErrorKind::ConnectionRefused => PortStatus::Closed,
                    _ => PortStatus::Filtered,
                }
            }
            Err(_) => {
                // Connection timed out
                PortStatus::Filtered
            }
        }
    }
}
