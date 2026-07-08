use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use futures::stream::{self, StreamExt};

use crate::model::{HostResult, HostStatus, PortResult, PortStatus, ScanResultSummary};
use crate::scanners::PortScanner;

pub async fn run_scan(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    scanner: Arc<dyn PortScanner>,
    concurrency: usize,
    timeout_duration: Duration,
) -> ScanResultSummary {
    let start_time = Instant::now();
    let total_hosts = hosts.len();
    
    // We will generate a list of all (ip, port) combinations to scan
    let mut scan_jobs = Vec::new();
    for &ip in &hosts {
        for &port in &ports {
            scan_jobs.push((ip, port));
        }
    }
    
    let total_jobs = scan_jobs.len();
    println!("[*] Starting {} scan of {} host(s) on {} port(s) (total {} probes)", scanner.name(), total_hosts, ports.len(), total_jobs);
    
    // Bounded concurrency using a semaphore
    let semaphore = Arc::new(Semaphore::new(concurrency));
    
    // Create an async stream of jobs
    let scanner_ref = Arc::clone(&scanner);
    let scan_stream = stream::iter(scan_jobs).map(|(ip, port)| {
        let sem = Arc::clone(&semaphore);
        let scan = Arc::clone(&scanner_ref);
        async move {
            // Acquire permit to limit concurrency
            let _permit = sem.acquire().await.unwrap();
            let status = scan.scan_port(ip, port, timeout_duration).await;
            (ip, port, status)
        }
    });
    
    // Run the stream concurrently, capturing results
    let mut results = scan_stream.buffer_unordered(concurrency);
    
    // We'll store results temporarily in a structure groupable by IP
    // Using a map would be convenient.
    use std::collections::HashMap;
    let mut host_ports: HashMap<IpAddr, Vec<PortResult>> = HashMap::new();
    for &ip in &hosts {
        host_ports.insert(ip, Vec::new());
    }
    
    let mut completed = 0;
    let update_interval = (total_jobs / 10).max(1);
    
    while let Some((ip, port, status)) = results.next().await {
        completed += 1;
        
        if status == PortStatus::Open {
            println!("[+] Found open port: {}:{}", ip, port);
        }
        
        if completed % update_interval == 0 || completed == total_jobs {
            println!("[*] Progress: {}/{} probes completed ({:.1}%)", 
                completed, total_jobs, (completed as f64 / total_jobs as f64) * 100.0);
        }
        
        if let Some(ports_list) = host_ports.get_mut(&ip) {
            ports_list.push(PortResult {
                port,
                status,
                service: None,
                banner: None,
            });
        }
    }
    
    // Finalize host list and statuses
    let mut hosts_up = 0;
    let mut host_results = Vec::new();
    
    for (ip, mut ports_list) in host_ports {
        // Sort ports back in ascending order
        ports_list.sort_by_key(|p| p.port);
        
        // Host is considered UP if at least one port is Open or Closed (not Filtered)
        let is_up = ports_list.iter().any(|p| p.status != PortStatus::Filtered);
        let status = if is_up {
            hosts_up += 1;
            HostStatus::Up
        } else {
            HostStatus::Down
        };
        
        host_results.push(HostResult {
            ip,
            status,
            ports: ports_list,
        });
    }
    
    // Sort hosts by IP address for clean output
    host_results.sort_by_key(|h| h.ip);
    
    let duration_ms = start_time.elapsed().as_millis() as u64;
    
    ScanResultSummary {
        targets_scanned: total_hosts,
        hosts_up,
        duration_ms,
        hosts: host_results,
    }
}
