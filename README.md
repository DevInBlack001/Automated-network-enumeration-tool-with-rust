# netenum — Automated Network Enumeration Toolkit 

An asynchronous network enumeration tool written in Rust, designed for high performance, pluggable scanning techniques, runtime capability detection, and optional deep enrichment via Nmap and custom NSE scripting.

---

## Architecture

This tool implements the architecture where the Rust engine serves as the core "brain". The native scanning layer executes async discovery and connect scans first. It then **optionally delegates to Nmap** for deep enrichment (`-sV` version signatures, `-O` OS detection, and target-selective NSE scripts) only on open ports, parsing the results from Nmap's XML output and merging them back into the native data model. 

When Nmap is not installed or when `--no-nmap` is passed, the tool **gracefully degrades** to native-only mode without breaking.

---

## Key Features

1. **Async Concurrency:** Built on the `tokio` multi-threaded runtime. It schedules thousands of concurrent probes utilizing a semaphore to prevent file-descriptor exhaustion.
2. **Dynamic Host Discovery:** Supports pre-scan host discovery sweeps using ICMP ping (unprivileged shell-out) and parallelized TCP connect probes.
3. **Runtime Capability Detection:** Checks for the presence of the `nmap` binary on the system `PATH` and verifies if the binary has raw socket permissions (`CAP_NET_RAW` / root privileges) to dynamically adjust host discovery and scanning options.
4. **Nmap Enrichment Layer:** Spawns asynchronous Nmap subprocesses to fetch version signatures and run scripts against identified open ports.
5. **Targeted NSE Scripting:** Automatically registers and executes targeted Lua scripts, such as the custom `NSE/etcd-info.nse` script when port `2379` is open, rather than blindly scanning with all scripts.
6. **Configuration Profiles:** Manage concurrency levels, timeouts, and discovery targets via structured TOML config profiles.
7. **Structured Reporting:** Output results directly to stdout or serialize them to custom JSON files for downstream processing.
8. **Scope Guardrails:** Refuses to run without an explicit `--i-have-authorization` acknowledgment, and supports `--allow`/`--deny` IP/CIDR lists (or files) to keep scans confined to an agreed-upon engagement scope.

---

## Directory Structure

```text
Network Enumeration Tool/
├── Cargo.toml               # Project dependencies (tokio, quick-xml, socket2, etc.)
├── profiles.toml            # TOML presets (quick, stealth, thorough)
├── README.md                # This documentation
├── src/
│   ├── main.rs              # Application entrypoint & CLI orchestrator
│   ├── cli.rs               # clap CLI argument definitions & parsing helpers
│   ├── config.rs            # Profile parsing and ScanConfig builder
│   ├── model.rs             # Scan Result and Host/Port data structures
│   ├── capabilities.rs      # Runtime capability probe (nmap, raw sockets)
│   ├── scope.rs             # Authorization gate + allow/deny scope policy
│   ├── targets/
│   │   ├── mod.rs
│   │   └── resolver.rs      # DNS lookup, IP parsing, and CIDR expansion
│   ├── discovery/
│   │   └── mod.rs           # ICMP and TCP ping sweeps with progress bars
│   ├── scanners/
│   │   ├── mod.rs           # PortScanner trait
│   │   └── connect.rs       # TCP Connect scanner implementation
│   ├── nmap/
│   │   ├── mod.rs           # Subprocess execution and XML result merging
│   │   ├── command.rs       # Dynamic argument building & targeted NSE selection
│   │   └── xml.rs           # Deserialization structures for Nmap XML output
│   ├── scripting/
│   │   └── mod.rs           # Embedded Lua scripting engine (mlua)
│   └── report/
│       ├── mod.rs
│       └── json.rs          # JSON report serializer
├── plugins/                 # Custom native Lua scripts/plugins
│   ├── http-title.lua       # Native HTTP page title grabber
│   └── banner-grab.lua      # Native TCP connection banner grabber
└── NSE/
    └── etcd-info.nse        # Custom Nmap script targeting unauthenticated etcd
```

---

## Getting Started

### Prerequisites

Ensure you have Rust and Cargo installed (MSRV 1.75+):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

To enable full enrichment features, install Nmap:
```bash
# Debian/Ubuntu
sudo apt-get install nmap

# RedHat/CentOS
sudo dnf install nmap
```

### Installation

1. Clone the repository and navigate to the directory:
   ```bash
   cd "Network Enumeration Tool"
   ```
2. Build the project in release mode:
   ```bash
   cargo build --release
   ```
3. Install the compiled binary system-wide:
   ```bash
   sudo mv target/release/netenum /usr/local/bin/
   ```

*Note on Global Execution:* Since `netenum` resolves relative paths (like `./NSE` and `./plugins`) based on your current shell directory, running it from a different folder requires passing absolute paths for NSE or Lua directories, or using a shell alias:
```bash
alias netenum="netenum --custom-nse-dir '/path/to/netenum/NSE' --custom-lua-dir '/path/to/netenum/plugins'"
```

---

## Usage Examples

> **Note:** every invocation below requires `--i-have-authorization`. netenum refuses to run
> without it — see [Scope & Authorization Guardrails](#scope--authorization-guardrails) below.

### 1. Basic Connect Scan & Nmap Enrichment (Default)
Scan ports 22, 80, 443, and 2379. If Nmap is installed, it will automatically enrich open ports with service version detection and scripts:
```bash
cargo run -- localhost -p 22,80,443,2379 --i-have-authorization
```

### 2. Skip Discovery & Scan All Ports
Scan the entire port range (`1-65535` is default) on a target host while skipping the pre-scan host discovery phase:
```bash
cargo run -- 192.168.1.100 --skip-discovery --i-have-authorization
```

### 3. Native-Only Mode (Bypass Nmap)
Force the scanner to run in native mode without spawning Nmap, even if it is available on the system:
```bash
cargo run -- localhost -p 22,80,443,2379 --no-nmap --i-have-authorization
```

### 4. Custom NSE Scripts Directory
Specify the path to the directory containing custom scripts (like `etcd-info.nse`):
```bash
cargo run -- localhost -p 2379 --custom-nse-dir ./NSE --i-have-authorization
```

### 5. Load TOML Scan Profile
Execute a scan using the `stealth` profile defined in `profiles.toml`:
```bash
cargo run -- 10.0.0.1 -p 80,443 -P profiles.toml --profile stealth --i-have-authorization
```

### 6. Save Scan Results to JSON
Scan and save the enriched results to a JSON file:
```bash
cargo run -- 10.0.0.1 -p 22,80,443 -o scan_output.json --i-have-authorization
```

### 7. Native SYN Scan (Privileged)
Use raw TCP packets to scan ports using SYN-ACK/RST responses. This requires root permissions or the `CAP_NET_RAW` capability:
```bash
sudo target/release/netenum localhost -p 22,80,443 --syn --i-have-authorization
```
*Note: If permissions are missing, netenum prints a warning and gracefully falls back to unprivileged TCP connect scans.*

### 8. Running SYN Scan Without Root (Linux Capabilities)
To run privileged raw socket scans without using `sudo` or running as the root user, you can grant the binary the `CAP_NET_RAW` capability:
```bash
sudo setcap cap_net_raw+ep target/release/netenum
target/release/netenum localhost -p 22,80,443 --syn --i-have-authorization
```

### 9. Custom Native Lua Plugins Directory
Specify the path to the directory containing native Lua script plugins (like `http-title.lua`):
```bash
cargo run -- localhost -p 8080 --custom-lua-dir ./plugins --i-have-authorization
```

### 10. Restrict Scanning to an Approved Scope
Only scan targets inside the agreed engagement range, even if a broader or unrelated target is passed by mistake; anything outside `--allow` (or inside `--deny`) is skipped with a warning instead of being scanned:
```bash
cargo run -- 10.0.0.0/24 --allow 10.0.0.0/24 --deny 10.0.0.1 --i-have-authorization
```
Allow/deny lists can also be loaded from files (one IP/CIDR per line, `#` comments supported):
```bash
cargo run -- 10.0.0.0/24 --allow-file scope-allow.txt --deny-file scope-deny.txt --i-have-authorization
```

---

## Scope & Authorization Guardrails

netenum performs active reconnaissance — port scans, banner grabs, service probes — against
real hosts. To reduce the chance of it being pointed at something out of scope by accident:

- **`--i-have-authorization`** is mandatory. Without it, netenum exits immediately before
  touching the network, printing a reminder to only scan systems you own or are explicitly
  authorized to test.
- **`--allow <IP/CIDR>`** (repeatable) / **`--allow-file <path>`**: if any allow entries are
  given, only resolved targets inside them are scanned — everything else is dropped with a
  warning, even if it was named explicitly on the command line.
- **`--deny <IP/CIDR>`** (repeatable) / **`--deny-file <path>`**: resolved targets inside a
  deny entry are always dropped, regardless of the allowlist.
- If every resolved target ends up out of scope, netenum exits with an error rather than
  silently scanning nothing.

---

## Custom Script: `etcd-info.nse`

The toolkit includes a custom NSE script `NSE/etcd-info.nse` designed to query etcd client ports (`2379`):
- It performs safe, read-only GET requests to endpoints such as `/version`, `/v2/stats/self`, and `/metrics`.
- It extracts the server and cluster versions, node role (leader vs. follower), and node name.
- It detects and reports public exposure of unauthenticated Prometheus metrics.
- When run under version detection (`-sV`), it enriches the Nmap service signature automatically.
