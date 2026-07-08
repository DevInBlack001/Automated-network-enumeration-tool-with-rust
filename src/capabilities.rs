use std::process::Command;
use socket2::{Socket, Domain, Type, Protocol};

/// Represents the system capabilities detected at runtime.
///
/// These detections guide the scanning strategy, determining whether netenum
/// can perform privileged raw packet operations (such as SYN scans) and whether
/// the Nmap binary is available on the system PATH to perform service enrichment.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// True if the `nmap` binary was found on the system PATH.
    pub nmap_present: bool,
    /// True if the program has permissions to open raw sockets (e.g., CAP_NET_RAW or running as root).
    pub has_raw_socket: bool,
}

impl Capabilities {
    pub fn detect() -> Self {
        let nmap_present = check_nmap();
        let has_raw_socket = check_raw_socket();
        Capabilities {
            nmap_present,
            has_raw_socket,
        }
    }
}

fn check_nmap() -> bool {
    Command::new("nmap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn check_raw_socket() -> bool {
    // Attempt to open a raw ICMP socket to test CAP_NET_RAW / root permissions.
    // We use libc::SOCK_RAW to construct Type to avoid platform-specific constant matching issues.
    let raw_type = Type::from(libc::SOCK_RAW);
    Socket::new(Domain::IPV4, raw_type, Some(Protocol::ICMPV4)).is_ok()
}
