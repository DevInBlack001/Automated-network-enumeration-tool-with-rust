use std::net::IpAddr;
use std::path::Path;
use crate::model::TransportProtocol;

pub struct NmapCommandBuilder {
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub protocol: TransportProtocol,
    pub version_detection: bool,
    pub os_detection: bool,
    pub scripts: Vec<String>,
}

impl NmapCommandBuilder {
    pub fn new(targets: Vec<IpAddr>, ports: Vec<u16>) -> Self {
        NmapCommandBuilder {
            targets,
            ports,
            protocol: TransportProtocol::Tcp,
            version_detection: true,
            os_detection: false,
            scripts: Vec::new(),
        }
    }

    pub fn with_protocol(mut self, protocol: TransportProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn with_os_detection(mut self, enabled: bool) -> Self {
        self.os_detection = enabled;
        self
    }

    pub fn with_version_detection(mut self, enabled: bool) -> Self {
        self.version_detection = enabled;
        self
    }

    pub fn with_script(mut self, script: String) -> Self {
        if !self.scripts.contains(&script) {
            self.scripts.push(script);
        }
        self
    }

    pub fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        // Output in XML format to stdout
        args.push("-oX".to_string());
        args.push("-".to_string());

        // Scan type: UDP datagram scan instead of the default TCP behavior
        if self.protocol == TransportProtocol::Udp {
            args.push("-sU".to_string());
        }

        // Version detection
        if self.version_detection {
            args.push("-sV".to_string());
        }

        // OS detection
        if self.os_detection {
            args.push("-O".to_string());
        }

        // Add ports
        if !self.ports.is_empty() {
            args.push("-p".to_string());
            let port_strings: Vec<String> = self.ports.iter().map(|p| p.to_string()).collect();
            args.push(port_strings.join(","));
        }

        // Add scripts
        if !self.scripts.is_empty() {
            args.push("--script".to_string());
            args.push(self.scripts.join(","));
        }

        // Add target IPs
        for ip in &self.targets {
            args.push(ip.to_string());
        }

        args
    }
}

/// Automatically registers custom scripts based on open ports found
pub fn auto_select_scripts(open_ports: &[u16], custom_nse_dir: &str) -> Vec<String> {
    let mut scripts = Vec::new();

    // If etcd port 2379 is open, attach the custom etcd-info script
    if open_ports.contains(&2379) {
        let script_path = Path::new(custom_nse_dir).join("etcd-info.nse");
        if script_path.exists() {
            if let Some(path_str) = script_path.to_str() {
                scripts.push(path_str.to_string());
            }
        } else {
            // Fallback to script name if not found in path
            scripts.push("etcd-info.nse".to_string());
        }
    }

    scripts
}
