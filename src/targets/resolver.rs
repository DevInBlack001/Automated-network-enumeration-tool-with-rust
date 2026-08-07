use std::collections::HashMap;
use std::net::IpAddr;
use ipnet::IpNet;
use tokio::net::lookup_host;
use std::str::FromStr;

pub async fn resolve_targets(target_strings: &[String]) -> Result<Vec<IpAddr>, String> {
    let mut resolved_ips = Vec::new();

    for target_str in target_strings {
        let target_str = target_str.trim();
        if target_str.is_empty() {
            continue;
        }

        // 1. Try to parse as single IP
        if let Ok(ip) = IpAddr::from_str(target_str) {
            resolved_ips.push(ip);
            continue;
        }

        // 2. Try to parse as CIDR network
        if let Ok(net) = IpNet::from_str(target_str) {
            match net {
                IpNet::V4(net_v4) => {
                    for ip in net_v4.hosts() {
                        resolved_ips.push(IpAddr::V4(ip));
                    }
                }
                IpNet::V6(net_v6) => {
                    for ip in net_v6.hosts() {
                        resolved_ips.push(IpAddr::V6(ip));
                    }
                }
            }
            continue;
        }

        // 3. Try to resolve as hostname
        let host_port = if target_str.contains(':') {
            target_str.to_string()
        } else {
            // Append a dummy port for DNS resolution since lookup_host requires it
            format!("{}:80", target_str)
        };

        match lookup_host(&host_port).await {
            Ok(addr_iter) => {
                let mut found = false;
                for socket_addr in addr_iter {
                    resolved_ips.push(socket_addr.ip());
                    found = true;
                }
                if !found {
                    return Err(format!("Could not resolve hostname: {}", target_str));
                }
            }
            Err(e) => {
                return Err(format!("Failed to resolve target '{}': {}", target_str, e));
            }
        }
    }

    // De-duplicate and keep stable order
    resolved_ips.dedup();

    Ok(resolved_ips)
}

/// Filters `target_strings` down to entries that are hostnames rather than a
/// raw IP or CIDR network — i.e. targets DNS enumeration can meaningfully run
/// against, since record queries (MX/TXT/NS/AXFR) need a domain name.
pub fn hostname_targets(target_strings: &[String]) -> Vec<String> {
    target_strings
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .filter(|s| IpAddr::from_str(s).is_err() && IpNet::from_str(s).is_err())
        .collect()
}

/// Resolves every hostname-form target and records which hostname each IP
/// came from. Callers that need a real SNI value rather than a bare IP (TLS
/// certificate inspection, in particular) use this: many TLS front-ends —
/// Cloudflare and shared hosting chief among them — hard-reject a handshake
/// that carries no SNI at all, even though they'll happily serve a bare IP
/// connection that does include one.
pub async fn hostname_ip_map(target_strings: &[String]) -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();
    for hostname in hostname_targets(target_strings) {
        if let Ok(addrs) = lookup_host(format!("{}:443", hostname)).await {
            for addr in addrs {
                map.entry(addr.ip()).or_insert_with(|| hostname.clone());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_targets_excludes_ips_and_cidrs() {
        let targets = vec![
            "example.com".to_string(),
            "192.168.1.1".to_string(),
            "10.0.0.0/24".to_string(),
            "sub.example.org".to_string(),
        ];
        assert_eq!(
            hostname_targets(&targets),
            vec!["example.com".to_string(), "sub.example.org".to_string()]
        );
    }
}
