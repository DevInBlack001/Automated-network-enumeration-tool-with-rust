use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;
use crate::model::PortStatus;

pub mod connect;
pub mod syn;

#[async_trait]
pub trait PortScanner: Send + Sync {
    fn name(&self) -> &'static str;
    #[allow(dead_code)]
    fn requires_raw_socket(&self) -> bool;
    async fn scan_port(&self, ip: IpAddr, port: u16, timeout: Duration) -> PortStatus;
}
