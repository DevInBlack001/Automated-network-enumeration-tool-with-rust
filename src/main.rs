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

use std::sync::Arc;
use std::time::Duration;
use clap::Parser;

use cli::{Cli, parse_ports};
use targets::resolver::resolve_targets;
use scanners::{PortScanner, connect::ConnectScanner, syn::SynScanner};
use engine::run_scan;
use report::json::save_to_json;
use config::{ConfigFile, ScanConfig};
use discovery::run_discovery;
use capabilities::Capabilities;
use nmap::NmapEnricher;

#[tokio::main]
async fn main() {
    // 1. Parse command line arguments
    let cli = Cli::parse();

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
    // we assign either the high-performance async ConnectScanner or the raw TCP SYN packet SynScanner.
    let scanner: Arc<dyn PortScanner> = if cli.syn {
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
        run_discovery(hosts, &scan_config).await
    };

    if scan_hosts.is_empty() {
        println!("[!] No live hosts discovered. Exiting.");
        std::process::exit(0);
    }

    // 7. Execute scan
    // Run the high-performance asynchronous port scanner concurrently with bounded semaphore limits.
    let timeout_duration = Duration::from_millis(scan_config.timeout_ms);
    let mut summary = run_scan(scan_hosts, ports, scanner, scan_config.concurrency, timeout_duration).await;

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

    // 9. Print summary
    println!("\n[*] Scan completed in {}ms", summary.duration_ms);
    println!("[*] Hosts up: {} / {}", summary.hosts_up, summary.targets_scanned);
    
    // Print a quick table of results to stdout
    println!("\nPORT      STATE    SERVICE      VERSION/BANNER");
    for host in &summary.hosts {
        if host.status == model::HostStatus::Up {
            println!("Results for {}:", host.ip);
            let mut open_ports = 0;
            for port_res in &host.ports {
                if port_res.status == model::PortStatus::Open {
                    let svc = port_res.service.as_deref().unwrap_or_else(|| get_common_service_name(port_res.port));
                    let banner = port_res.banner.as_deref().unwrap_or("");
                    if banner.is_empty() {
                        println!("{:<9}/tcp open     {:<12}", port_res.port, svc);
                    } else {
                        println!("{:<9}/tcp open     {:<12} {}", port_res.port, svc, banner);
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

// Simple lookup for common ports to show service name in stdout
fn get_common_service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        2379 => "etcd",
        8080 => "http-proxy",
        _ => "unknown",
    }
}
