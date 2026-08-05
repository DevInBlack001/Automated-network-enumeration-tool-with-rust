pub mod command;
pub mod xml;

use std::net::IpAddr;
use tokio::process::Command;
use crate::model::{ScanResultSummary, PortStatus, TransportProtocol};
use crate::capabilities::Capabilities;
use command::{NmapCommandBuilder, auto_select_scripts};
use xml::NmapRun;

pub struct NmapEnricher {
    pub custom_nse_dir: String,
}

impl NmapEnricher {
    pub fn new(custom_nse_dir: String) -> Self {
        NmapEnricher { custom_nse_dir }
    }

    pub fn available(&self, caps: &Capabilities) -> bool {
        caps.nmap_present
    }

    pub async fn enrich(
        &self,
        summary: &mut ScanResultSummary,
        caps: &Capabilities,
    ) -> Result<(), String> {
        if !self.available(caps) {
            return Err("Nmap is not present on the system PATH.".to_string());
        }

        // 1. Collect live host IPs and union of open (or ambiguous) ports.
        // Every port in a single run shares the same protocol, since main.rs picks
        // one scanner (TCP connect/SYN, or UDP) for the whole scan.
        let mut live_ips = Vec::new();
        let mut open_ports = Vec::new();
        let mut protocol = TransportProtocol::Tcp;

        for host in &summary.hosts {
            if host.status == crate::model::HostStatus::Up {
                live_ips.push(host.ip);
                for port_res in &host.ports {
                    if port_res.status == PortStatus::Open || port_res.status == PortStatus::OpenFiltered {
                        open_ports.push(port_res.port);
                        protocol = port_res.protocol;
                    }
                }
            }
        }

        if live_ips.is_empty() || open_ports.is_empty() {
            println!("[*] No open ports found to enrich with Nmap.");
            return Ok(());
        }

        // De-duplicate and sort open ports
        open_ports.sort_unstable();
        open_ports.dedup();

        println!(
            "[*] Spawning Nmap to enrich {} host(s) on open ports: {:?}",
            live_ips.len(),
            open_ports
        );

        // 2. Build Nmap Command
        let mut builder = NmapCommandBuilder::new(live_ips.clone(), open_ports.clone())
            .with_protocol(protocol)
            .with_version_detection(true)
            .with_os_detection(caps.has_raw_socket); // OS detection requires raw socket privilege

        // Auto-select and attach scripts
        let scripts = auto_select_scripts(&open_ports, &self.custom_nse_dir);
        for script in scripts {
            println!("[*] Attaching NSE script: {}", script);
            builder = builder.with_script(script);
        }

        let args = builder.build_args();
        println!("[*] Running: nmap {}", args.join(" "));

        // 3. Run command
        let output = Command::new("nmap")
            .args(&args)
            .output()
            .await
            .map_err(|e| format!("Failed to spawn Nmap: {}", e))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Nmap failed with exit status: {}\nError: {}", output.status, err_msg));
        }

        // 4. Parse XML output
        let xml_str = String::from_utf8_lossy(&output.stdout);
        let nmap_run: NmapRun = quick_xml::de::from_str(&xml_str)
            .map_err(|e| format!("Failed to parse Nmap XML output: {}", e))?;

        // 5. Merge results back
        for parsed_host in nmap_run.hosts {
            // Find host IP
            let mut host_ip = None;
            for addr in &parsed_host.addresses {
                if addr.addr_type == "ipv4" || addr.addr_type == "ipv6" {
                    if let Ok(ip) = addr.addr.parse::<IpAddr>() {
                        host_ip = Some(ip);
                        break;
                    }
                }
            }

            let host_ip = match host_ip {
                Some(ip) => ip,
                None => continue,
            };

            // Find host in our summary
            if let Some(host_res) = summary.hosts.iter_mut().find(|h| h.ip == host_ip) {
                if let Some(container) = parsed_host.ports_container {
                    for parsed_port in container.ports {
                        // Find port in our host_res
                        if let Some(port_res) = host_res.ports.iter_mut().find(|p| p.port == parsed_port.port_id) {
                            // Extract service name
                            if let Some(service) = parsed_port.service.as_ref() {
                                if let Some(name) = service.name.as_ref() {
                                    port_res.service = Some(name.clone());
                                    // Nmap reports match confidence on a 0-10 scale; default to a
                                    // reasonably high value on the rare case it's omitted from XML.
                                    let conf = service.conf.map(|c| c.saturating_mul(10).min(100)).unwrap_or(70);
                                    port_res.confidence = Some(conf);
                                    port_res.confidence_source = Some(crate::model::ServiceSource::NmapProbe);
                                }

                                // Construct version banner, extending any banner a native
                                // Lua plugin already wrote for this port rather than
                                // discarding it.
                                let mut banner = port_res.banner.take().unwrap_or_default();
                                let had_existing_banner = !banner.is_empty();
                                if let Some(product) = service.product.as_ref() {
                                    if had_existing_banner {
                                        banner.push_str(" | ");
                                    }
                                    banner.push_str(product);
                                }
                                if let Some(version) = service.version.as_ref() {
                                    if !banner.is_empty() {
                                        banner.push_str(" ");
                                    }
                                    banner.push_str(version);
                                }
                                if let Some(extrainfo) = service.extra_info.as_ref() {
                                    if !banner.is_empty() {
                                        banner.push_str(" ");
                                    }
                                    banner.push_str(&format!("({})", extrainfo));
                                }

                                if !banner.is_empty() {
                                    port_res.banner = Some(banner);
                                }
                            }

                            // Append script outputs to banner if present
                            for script in &parsed_port.scripts {
                                if let Some(script_out) = script.output.as_ref() {
                                    let mut current_banner = port_res.banner.take().unwrap_or_default();
                                    if !current_banner.is_empty() {
                                        current_banner.push_str(" | ");
                                    }
                                    current_banner.push_str(&format!("{}: {}", script.id, script_out.trim()));
                                    port_res.banner = Some(current_banner);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
