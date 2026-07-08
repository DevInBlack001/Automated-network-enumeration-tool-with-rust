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

    /// Disable Nmap enrichment layer (force native-only mode)
    #[arg(long = "no-nmap")]
    pub no_nmap: bool,

    /// Use native SYN scan (requires CAP_NET_RAW / root privileges)
    #[arg(long = "syn")]
    pub syn: bool,

    /// Path to custom NSE directory. Defaults to "./NSE"
    #[arg(long = "custom-nse-dir", default_value = "./NSE")]
    pub custom_nse_dir: String,

    /// Path to custom Lua plugins directory. Defaults to "./plugins"
    #[arg(long = "custom-lua-dir", default_value = "./plugins")]
    pub custom_lua_dir: String,
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
