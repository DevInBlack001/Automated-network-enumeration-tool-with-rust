mod model;
mod cli;
mod targets;
mod scanners;
mod engine;
mod report;
mod config;
mod discovery;
mod capabilities;
mod nmap;
mod scripting;
mod scope;
mod banner;
mod udp_identify;
mod enumeration;

use std::sync::Arc;
use std::time::Duration;
use clap::Parser;

use cli::{Cli, parse_ports};
use targets::resolver::{resolve_targets, hostname_targets};
use scanners::{PortScanner, connect::ConnectScanner, syn::SynScanner, udp::UdpScanner};
use engine::run_scan;
use report::json::save_to_json;
use config::{ConfigFile, ScanConfig};
use discovery::run_discovery;
use capabilities::Capabilities;
use nmap::NmapEnricher;
use scope::ScopePolicy;

#[tokio::main]
async fn main() {
    // 1. Parse command line arguments
    let cli = Cli::parse();

    // 1.5 Refuse to run at all without an explicit authorization acknowledgment.
    // This must happen before any network activity, including capability probing.
    if !cli.authorized {
        eprintln!("[!] Refusing to scan: no authorization acknowledgment given.");
        eprintln!("    netenum performs active reconnaissance (port scans, banner grabs, service probes).");
        eprintln!("    Only run it against systems you own or have explicit written permission to test.");
        eprintln!("    Re-run with --i-have-authorization once you've confirmed you're authorized.");
        std::process::exit(1);
    }

    let scope_policy = match ScopePolicy::build(&cli.allow, &cli.allow_file, &cli.deny, &cli.deny_file) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("[!] Scope configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Detect system capabilities
    let caps = Capabilities::detect();
    println!("[*] Detecting system capabilities...");
    println!("    - Nmap binary found: {}", caps.nmap_present);
    println!("    - Raw socket permissions: {}", caps.has_raw_socket);

    // 2. Load and resolve configuration
    let mut profile = None;
    let mut config_file = None;

    if let Some(ref path) = cli.profile_path {
        match ConfigFile::load_from_file(path) {
            Ok(cfg) => {
                config_file = Some(cfg);
            }
            Err(e) => {
                eprintln!("[!] Configuration error: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref name) = cli.profile_name {
        if let Some(ref cfg) = config_file {
            profile = cfg.profiles.get(name);
            if profile.is_none() {
                eprintln!("[!] Error: Profile '{}' not found in profiles file.", name);
                std::process::exit(1);
            }
        } else {
            eprintln!("[!] Error: Profile name specified without a profiles file path (--profile-path / -P).");
            std::process::exit(1);
        }
    } else if let Some(ref cfg) = config_file {
        profile = cfg.profiles.get("default");
        if profile.is_none() {
            profile = cfg.profiles.values().next();
            if let Some(_) = profile {
                println!("[*] No profile specified, using first available profile.");
            }
        }
    }

    let mut scan_config = ScanConfig::merge(cli.concurrency, cli.timeout, profile);

    // Apply CLI overrides
    if cli.no_ping {
        scan_config.ping_discovery = false;
    }

    // 3. Resolve target hosts
    let hosts = match resolve_targets(&cli.targets).await {
        Ok(ips) => {
            if ips.is_empty() {
                eprintln!("[!] Error: No targets resolved from input.");
                std::process::exit(1);
            }
            ips
        }
        Err(e) => {
            eprintln!("[!] Target resolution error: {}", e);
            std::process::exit(1);
        }
    };

    // 3.5 Enforce scope guardrails (allowlist/denylist) on the resolved targets.
    let (hosts, out_of_scope) = scope_policy.partition(hosts);
    if !out_of_scope.is_empty() {
        println!("[!] {} target(s) excluded by scope policy:", out_of_scope.len());
        for ip in &out_of_scope {
            println!("    - {}", ip);
        }
    }
    if hosts.is_empty() {
        eprintln!("[!] Error: All resolved targets are outside the configured scope.");
        std::process::exit(1);
    }

    // 4. Parse ports
    let ports = match parse_ports(&cli.ports) {
        Ok(p) => {
            if p.is_empty() {
                eprintln!("[!] Error: No ports specified or parsed.");
                std::process::exit(1);
            }
            p
        }
        Err(e) => {
            eprintln!("[!] Port parsing error: {}", e);
            std::process::exit(1);
        }
    };

    // 5. Initialize scanner
    // Based on CLI flags and detected system capabilities (root vs unprivileged),
    // we assign either the high-performance async ConnectScanner, the raw TCP SYN
    // packet SynScanner, or the UdpScanner for UDP datagram probing.
    let scanner: Arc<dyn PortScanner> = if cli.udp {
        println!("[*] Using UDP scan mode.");
        println!("    Note: UDP results are inherently ambiguous (no response = open|filtered).");
        println!("    Narrow --ports and/or raise --timeout for more reliable results.");
        Arc::new(UdpScanner::new())
    } else if cli.syn {
        if caps.has_raw_socket {
            println!("[*] Using native SYN scan (privileged mode).");
            Arc::new(SynScanner::new())
        } else {
            println!("[!] Warning: SYN scan requested but CAP_NET_RAW / root privileges are missing.");
            println!("    Falling back to TCP connect scan.");
            Arc::new(ConnectScanner)
        }
    } else {
        Arc::new(ConnectScanner)
    };

    println!("[*] Starting netenum scan...");
    println!("[*] Target count: {}", hosts.len());
    println!("[*] Port count: {}", ports.len());
    println!("[*] Concurrency: {}", scan_config.concurrency);
    println!("[*] Timeout: {}ms", scan_config.timeout_ms);

    // 6. Run host discovery
    // Perform an initial ICMP ping and/or TCP ACK/SYN ping sweeps to verify if hosts are live,
    // reducing time wasted scanning dead IP addresses.
    let scan_hosts = if cli.skip_discovery {
        println!("[*] Skipping host discovery. Scanning all {} target(s) directly.", hosts.len());
        hosts
    } else {
        let arp_enabled = if cli.arp && !caps.has_raw_socket {
            println!("[!] Warning: ARP discovery requested but CAP_NET_RAW / root privileges are missing.");
            println!("    Falling back to ICMP/TCP ping discovery.");
            false
        } else {
            cli.arp
        };
        run_discovery(hosts, &scan_config, arp_enabled).await
    };

    if scan_hosts.is_empty() {
        println!("[!] No live hosts discovered. Exiting.");
        std::process::exit(0);
    }

    // 7. Execute scan
    // Run the high-performance asynchronous port scanner concurrently with bounded semaphore limits.
    let timeout_duration = Duration::from_millis(scan_config.timeout_ms);
    let mut summary = run_scan(scan_hosts, ports, scanner, scan_config.concurrency, timeout_duration).await;

    // 7.4 Generic native banner grab (no Nmap, no port-specific script required)
    // Probes every open TCP port that doesn't already have a banner: reads whatever
    // the service sends unprompted, or falls back to a generic HTTP/1.0 request.
    println!("[*] Grabbing native service banners...");
    banner::grab_banners(&mut summary, scan_config.timeout_ms).await;

    // 7.45 Identify UDP services (DNS/NTP/SNMP) by re-probing with the real
    // protocol request and validating the response structure -- tried against
    // every open UDP port regardless of port number, not gated by it.
    println!("[*] Identifying UDP services...");
    udp_identify::identify_services(&mut summary, scan_config.timeout_ms).await;

    // 7.5 Run native Lua script plugins
    // Scan `./plugins` directory for user-defined native Lua scripts (e.g. HTTP title extraction,
    // FTP banner grabs) and execute them against discovered open ports.
    scripting::run_plugins(&mut summary, &cli.custom_lua_dir).await;

    // 8. Run Nmap enrichment if available and not disabled
    // If the system has nmap installed, run target service/OS/NSE signature scans on found open ports
    // and seamlessly merge nmap's XML findings back into the native Rust results.
    if !cli.no_nmap && caps.nmap_present {
        println!("\n[*] Running Nmap enrichment...");
        let enricher = NmapEnricher::new(cli.custom_nse_dir.clone());
        if let Err(e) = enricher.enrich(&mut summary, &caps).await {
            eprintln!("[!] Nmap enrichment failed: {}", e);
        } else {
            println!("[+] Nmap enrichment complete.");
        }
    } else if !cli.no_nmap && !caps.nmap_present {
        println!("\n[*] Nmap not found on system PATH. Skipping enrichment.");
    }

    // 8.5 DNS enumeration, opt-in via --dns. Only applies to hostname-form
    // targets -- record queries (MX/TXT/NS/AXFR) need a domain name, not an IP.
    if cli.dns {
        let dns_targets = hostname_targets(&cli.targets);
        if dns_targets.is_empty() {
            println!("\n[*] --dns given but no hostname-form targets to enumerate (only IPs/CIDRs were provided).");
        }
        for domain in &dns_targets {
            println!("\n[*] Running DNS enumeration for {}...", domain);
            match enumeration::dns::enumerate(domain).await {
                Ok((_primary_ip, mut findings)) => {
                    println!("[+] DNS enumeration complete for {} ({} finding(s)).", domain, findings.len());
                    summary.findings.append(&mut findings);
                }
                Err(e) => {
                    eprintln!("[!] DNS enumeration failed for {}: {}", domain, e);
                }
            }
        }
    }

    // 8.6 HTTP fingerprinting, opt-in via --http. Runs against every open port
    // already identified as an HTTP service, regardless of how the target was given.
    if cli.http {
        println!("\n[*] Running HTTP fingerprinting...");
        let mut http_findings = Vec::new();
        for host in &summary.hosts {
            if host.status == model::HostStatus::Up {
                http_findings.extend(enumeration::http::enumerate_host(host, scan_config.timeout_ms).await);
            }
        }
        println!("[+] HTTP fingerprinting complete ({} finding(s)).", http_findings.len());
        summary.findings.extend(http_findings);
    }

    // 9. Print summary
    println!("\n[*] Scan completed in {}ms", summary.duration_ms);
    println!("[*] Hosts up: {} / {}", summary.hosts_up, summary.targets_scanned);

    // Print a quick table of results to stdout
    println!("\nPORT      PROTO STATE          SERVICE      CONFIDENCE      VERSION/BANNER");
    for host in &summary.hosts {
        if host.status == model::HostStatus::Up {
            println!("Results for {}:", host.ip);
            if let Some(os) = &host.os {
                println!("OS: {} ({}% accuracy)", os.name, os.accuracy);
            }
            let mut open_ports = 0;
            for port_res in &host.ports {
                if port_res.status == model::PortStatus::Open || port_res.status == model::PortStatus::OpenFiltered {
                    let proto = match port_res.protocol {
                        model::TransportProtocol::Tcp => "tcp",
                        model::TransportProtocol::Udp => "udp",
                    };
                    let state = match port_res.status {
                        model::PortStatus::Open => "open",
                        model::PortStatus::OpenFiltered => "open|filtered",
                        _ => unreachable!(),
                    };
                    let svc = port_res.service.as_deref().unwrap_or("unknown");
                    let conf = match (port_res.confidence, port_res.confidence_source) {
                        (Some(c), Some(model::ServiceSource::NmapProbe)) => format!("{}% (nmap)", c),
                        (Some(c), Some(model::ServiceSource::NativeBanner)) => format!("{}% (banner)", c),
                        _ => "-".to_string(),
                    };
                    let mut banner = port_res.banner.clone().unwrap_or_default();
                    if !port_res.cpe.is_empty() {
                        if !banner.is_empty() {
                            banner.push_str(" | ");
                        }
                        banner.push_str(&port_res.cpe.join(", "));
                    }
                    if banner.is_empty() {
                        println!("{:<9} {:<5} {:<14} {:<12} {:<15}", port_res.port, proto, state, svc, conf);
                    } else {
                        println!("{:<9} {:<5} {:<14} {:<12} {:<15} {}", port_res.port, proto, state, svc, conf, banner);
                    }
                    open_ports += 1;
                }
            }
            if open_ports == 0 {
                println!("(No open ports found)");
            }
            println!();
        }
    }

    // Print enumeration findings, if any were gathered
    if !summary.findings.is_empty() {
        println!("FINDINGS ({}):", summary.findings.len());
        for finding in &summary.findings {
            let severity = format!("{:?}", finding.severity).to_uppercase();
            println!("[{}] {} - {}", severity, finding.id, finding.evidence);
            if !finding.recommendation.is_empty() {
                println!("    -> {}", finding.recommendation);
            }
        }
        println!();
    }

    // 10. Save output if requested
    if let Some(ref path) = cli.output {
        println!("[*] Saving results to {}...", path);
        if let Err(e) = save_to_json(&summary, path) {
            eprintln!("[!] Error saving JSON results: {}", e);
        } else {
            println!("[+] Results saved successfully.");
        }
    }
}
