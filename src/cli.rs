use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "netenum", version, about = "Async Network Enumeration Tool in Rust")]
pub struct Cli {
    /// Target hosts (e.g. 192.168.1.1, 10.0.0.0/24, localhost)
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Ports to scan (e.g., "80", "22,80,443", "1-65535"). Defaults to 1-65535.
    #[arg(short = 'p', long = "ports", default_value = "1-65535")]
    pub ports: String,

    /// Max concurrent connection attempts (semaphore limit)
    #[arg(short = 'c', long = "concurrency", default_value_t = 1000)]
    pub concurrency: usize,

    /// Target connection timeout in milliseconds
    #[arg(long = "timeout", default_value_t = 1500)]
    pub timeout: u64,

    /// Save results to a file in JSON format
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Path to a TOML profiles config file (e.g., profiles.toml)
    #[arg(short = 'P', long = "profile-path")]
    pub profile_path: Option<String>,

    /// Name of the profile to use from the TOML file
    #[arg(long = "profile")]
    pub profile_name: Option<String>,

    /// Skip host discovery and scan all target IPs directly
    #[arg(long = "skip-discovery")]
    pub skip_discovery: bool,

    /// Disable ICMP ping sweeps during host discovery
    #[arg(long = "no-ping")]
    pub no_ping: bool,

    /// Use ARP requests to discover local LAN hosts before scanning (requires
    /// CAP_NET_RAW / root privileges). Falls back to ICMP/TCP ping discovery for
    /// targets outside every local subnet, or if privileges are missing.
    #[arg(long = "arp")]
    pub arp: bool,

    /// Disable Nmap enrichment layer (force native-only mode)
    #[arg(long = "no-nmap")]
    pub no_nmap: bool,

    /// Use native SYN scan (requires CAP_NET_RAW / root privileges)
    #[arg(long = "syn", conflicts_with = "udp")]
    pub syn: bool,

    /// Scan via UDP datagrams instead of TCP (mutually exclusive with --syn)
    #[arg(long = "udp", conflicts_with = "syn")]
    pub udp: bool,

    /// Path to custom NSE directory. Defaults to "./NSE"
    #[arg(long = "custom-nse-dir", default_value = "./NSE")]
    pub custom_nse_dir: String,

    /// Path to custom Lua plugins directory. Defaults to "./plugins"
    #[arg(long = "custom-lua-dir", default_value = "./plugins")]
    pub custom_lua_dir: String,

    /// Explicit acknowledgment that you own or have written permission to scan every
    /// target given. netenum performs active reconnaissance (port scans, banner grabs,
    /// service probes) and refuses to run without this flag.
    #[arg(long = "i-have-authorization")]
    pub authorized: bool,

    /// Restrict scanning to this IP/CIDR (repeatable). If any --allow entries are
    /// given, targets outside all of them are skipped even if passed on the command line.
    #[arg(long = "allow")]
    pub allow: Vec<String>,

    /// Path to a file of allowed IPs/CIDRs, one per line ('#' comments supported).
    #[arg(long = "allow-file")]
    pub allow_file: Option<String>,

    /// Exclude this IP/CIDR from scanning (repeatable). Denylist entries always win over the allowlist.
    #[arg(long = "deny")]
    pub deny: Vec<String>,

    /// Path to a file of denied IPs/CIDRs, one per line ('#' comments supported).
    #[arg(long = "deny-file")]
    pub deny_file: Option<String>,

    /// Run DNS enumeration (A/AAAA/CNAME/NS/MX/TXT records, reverse DNS, and an
    /// AXFR zone transfer probe) against every hostname-form target given.
    /// Has no effect on targets given as a raw IP or CIDR.
    #[arg(long = "dns")]
    pub dns: bool,

    /// Run HTTP fingerprinting (page title, tech-revealing response headers)
    /// against every open port identified as an HTTP service.
    #[arg(long = "http")]
    pub http: bool,
}

/// Parses a port string which can contain comma-separated values and ranges (e.g. "22,80,443,1000-2000")
pub fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in port_str.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid port range format: {}", part));
            }
            let start = bounds[0]
                .parse::<u16>()
                .map_err(|_| format!("Invalid start port: {}", bounds[0]))?;
            let end = bounds[1]
                .parse::<u16>()
                .map_err(|_| format!("Invalid end port: {}", bounds[1]))?;
            if start > end {
                return Err(format!("Start port {} is greater than end port {}", start, end));
            }
            for port in start..=end {
                ports.push(port);
            }
        } else {
            let port = part
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", part))?;
            ports.push(port);
        }
    }
    
    // De-duplicate and sort ports
    ports.sort_unstable();
    ports.dedup();
    
    Ok(ports)
}
