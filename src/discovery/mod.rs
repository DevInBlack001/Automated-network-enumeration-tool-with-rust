use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::process::Command;
use tokio::sync::Semaphore;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};

use crate::config::ScanConfig;

pub mod arp;

/// Perform ICMP ping by shelling out to the system 'ping' utility (which has capabilities to run unprivileged).
async fn ping_host(ip: IpAddr, timeout_ms: u64) -> bool {
    let ip_str = ip.to_string();
    
    // Determine command and arguments based on IP family
    let (cmd, args) = if ip.is_ipv6() {
        ("ping", vec!["-6", "-c", "1", "-W", "1", &ip_str])
    } else {
        ("ping", vec!["-c", "1", "-W", "1", &ip_str])
    };

    let mut child = match Command::new(cmd)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn() 
    {
        Ok(c) => c,
        Err(_) => return false, // If ping binary not found/executable, fail gracefully
    };

    let wait_timeout = Duration::from_millis(timeout_ms);
    match timeout(wait_timeout, child.wait()).await {
        Ok(Ok(status)) => status.success(),
        _ => {
            let _ = child.kill().await;
            false
        }
    }
}

/// Perform TCP ping check by attempting connections to a list of common ports in parallel.
async fn tcp_ping_host(ip: IpAddr, ports: &[u16], timeout_ms: u64) -> bool {
    if ports.is_empty() {
        return false;
    }

    let timeout_duration = Duration::from_millis(timeout_ms);
    
    let probes = ports.iter().map(|&port| {
        let addr = SocketAddr::new(ip, port);
        async move {
            match timeout(timeout_duration, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => true, // Connection succeeded
                Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => true, // Host responded with RST, meaning it is alive
                _ => false,
            }
        }
    });

    // Run probes concurrently and check if any succeeded
    let mut results = stream::iter(probes).buffer_unordered(ports.len());
    while let Some(success) = results.next().await {
        if success {
            return true;
        }
    }

    false
}

/// Check if a target host is alive using ICMP ping and/or TCP port probes.
async fn is_host_alive(ip: IpAddr, config: &ScanConfig) -> bool {
    // 1. Try ICMP Ping first if enabled
    if config.ping_discovery {
        if ping_host(ip, config.timeout_ms).await {
            return true;
        }
    }

    // 2. Fall back to TCP Ping probes
    if !config.tcp_ping_ports.is_empty() {
        if tcp_ping_host(ip, &config.tcp_ping_ports, config.timeout_ms).await {
            return true;
        }
    }

    false
}

/// Run host discovery across all target addresses with concurrency control and a progress bar.
///
/// When `arp_enabled` is set, IPv4 targets on a locally-connected subnet are resolved
/// via a batch of ARP requests first (fast and reliable on a LAN, no firewall to worry
/// about); everything ARP doesn't cover falls through to the usual ICMP/TCP ping sweep.
pub async fn run_discovery(targets: Vec<IpAddr>, config: &ScanConfig, arp_enabled: bool) -> Vec<IpAddr> {
    let total_targets = targets.len();
    if total_targets == 0 {
        return Vec::new();
    }

    let mut alive_hosts: Vec<IpAddr> = Vec::new();
    let mut remaining_targets = targets;

    if arp_enabled {
        let ipv4_targets: Vec<Ipv4Addr> = remaining_targets
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect();

        if !ipv4_targets.is_empty() {
            println!("[*] Running ARP discovery for locally-reachable IPv4 target(s)...");
            let arp_timeout = Duration::from_millis(config.timeout_ms);
            let found = tokio::task::spawn_blocking(move || arp::arp_discover(&ipv4_targets, arp_timeout))
                .await
                .unwrap_or_default();
            println!("[+] ARP discovery found {} live host(s)", found.len());

            remaining_targets.retain(|ip| match ip {
                IpAddr::V4(v4) => !found.contains(v4),
                IpAddr::V6(_) => true,
            });
            alive_hosts.extend(found.into_iter().map(IpAddr::V4));
        }
    }

    if remaining_targets.is_empty() {
        alive_hosts.sort();
        println!("[+] Discovered {} live host(s) out of {} target(s)", alive_hosts.len(), total_targets);
        return alive_hosts;
    }

    println!("[*] Starting host discovery for {} target address(es)...", remaining_targets.len());

    let pb = ProgressBar::new(remaining_targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) - {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Discovering live hosts");

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let config_arc = Arc::new(config.clone());

    let discovery_stream = stream::iter(remaining_targets).map(|ip| {
        let sem = Arc::clone(&semaphore);
        let cfg = Arc::clone(&config_arc);
        let pb_clone = pb.clone();
        async move {
            let _permit = sem.acquire().await.unwrap();
            let alive = is_host_alive(ip, &cfg).await;
            pb_clone.inc(1);
            if alive {
                (ip, true)
            } else {
                (ip, false)
            }
        }
    });

    let mut results = discovery_stream.buffer_unordered(config.concurrency);

    while let Some((ip, alive)) = results.next().await {
        if alive {
            alive_hosts.push(ip);
        }
    }

    pb.finish_with_message("Host discovery complete");
    println!("[+] Discovered {} live host(s) out of {} target(s)", alive_hosts.len(), total_targets);

    // Keep the order of alive hosts stable
    alive_hosts.sort();
    alive_hosts
}
