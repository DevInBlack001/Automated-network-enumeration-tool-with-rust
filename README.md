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
9. **UDP Scanning:** `--udp` switches the scanner to UDP datagram probes (with protocol-aware payloads for DNS/NTP/SNMP), detecting closed ports via ICMP port-unreachable without requiring raw-socket privileges.
10. **ARP Host Discovery:** `--arp` resolves IPv4 targets on a locally-connected subnet via a batch of raw ARP requests (faster and firewall-proof on a LAN) before falling back to ICMP/TCP ping for anything ARP can't reach.
11. **Generic Native Banner Grabbing & Signature Identification:** Every open TCP port without a banner is probed directly (`src/banner.rs`) — reading whatever the service sends unprompted, or falling back to a generic HTTP/1.0 request — then identified by matching the actual response against distinctive protocol signatures (an `SSH-` prefix, an HTTP status line, an RFB/VNC handshake, etc.), not by port number. No live evidence means no service name is reported; nothing is ever fabricated from a hardcoded port table.
12. **Native UDP Service Identification:** Every open/ambiguous UDP port is re-probed with real DNS, NTP, and SNMP requests (`src/udp_identify.rs`), tried against *any* port regardless of number, and only confirmed when the response is structurally valid for that protocol (e.g. a DNS reply must echo the transaction ID with the response flag set; an SNMP reply must contain a GetResponse-PDU and echo the community string) — not just "something answered".
13. **Service/Version Confidence Scoring:** Every identified service carries a `confidence` (0-100) and `confidence_source` — `nmap` (probe/signature match) or `banner` (live content-based signature match) — so you can tell at a glance how the SERVICE label was determined, both in the stdout table and the JSON report.
14. **OS Fingerprinting Summary:** When Nmap's `-O` detection runs (requires `CAP_NET_RAW`/root), the highest-accuracy OS match is parsed from its XML output and surfaced per host — e.g. `OS: Linux 4.15 - 5.6 (98% accuracy)` — in both stdout and the JSON report.

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
│   ├── banner.rs            # Native TCP banner grabbing + content-based signature identification
│   ├── udp_identify.rs      # Native UDP service identification (DNS/NTP/SNMP structural validation)
│   ├── targets/
│   │   ├── mod.rs
│   │   └── resolver.rs      # DNS lookup, IP parsing, and CIDR expansion
│   ├── discovery/
│   │   ├── mod.rs           # ICMP and TCP ping sweeps with progress bars
│   │   └── arp.rs           # Raw ARP request/reply host discovery for local subnets
│   ├── scanners/
│   │   ├── mod.rs           # PortScanner trait
│   │   ├── connect.rs       # TCP Connect scanner implementation
│   │   ├── syn.rs           # Raw TCP SYN scanner implementation
│   │   └── udp.rs           # UDP datagram scanner implementation
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
│   └── http-title.lua       # Native HTTP page title extractor (raw banner grabbing is now handled natively for every port; see src/banner.rs)
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

### 10. UDP Scan
Scan common UDP services (DNS, NTP, SNMP get protocol-specific probe payloads; other ports get an empty datagram). No response within the timeout is reported as `open|filtered`, matching Nmap's own UDP ambiguity; a closed port is detected via an ICMP port-unreachable response, no root required:
```bash
cargo run -- 10.0.0.1 -p 53,123,161,500 --udp --i-have-authorization
```

### 11. ARP Host Discovery on a Local LAN
Resolve which IPv4 targets on your local subnet are alive via raw ARP requests instead of ICMP/TCP ping (requires root or `CAP_NET_RAW`; falls back automatically for targets outside any local subnet, or if privileges are missing):
```bash
sudo target/release/netenum 192.168.1.0/24 --arp --i-have-authorization
```

### 12. Native Banner Grabbing & Signature Identification (No Nmap)
Even without Nmap, netenum captures real service banners from *any* open TCP port, not just a fixed list — it reads whatever the service sends unprompted (or falls back to a generic HTTP/1.0 request), then identifies the service by matching that content against distinctive protocol signatures. A port with no response, or a response that doesn't match anything recognizable, is honestly reported as `unknown` — never a fabricated guess based on the port number:
```bash
cargo run -- 10.0.0.1 -p 1-65535 --no-nmap --i-have-authorization
```

### 13. UDP Service Identification (DNS/NTP/SNMP)
Open UDP ports get the same evidence-based treatment: netenum re-sends the real DNS/NTP/SNMP request and only confirms the service if the response is structurally valid for that protocol — tried against any port, not just 53/123/161:
```bash
cargo run -- 10.0.0.1 --udp -p 53,123,161,9999 --no-nmap --i-have-authorization
```

### 14. Reading Service Confidence in Output
Every open port's SERVICE label comes with a confidence tag showing how it was determined:
```text
PORT      PROTO STATE          SERVICE      CONFIDENCE      VERSION/BANNER
22        tcp   open           ssh          90% (banner)    SSH-2.0-OpenSSH_9.6
443       tcp   open           https        70% (nmap)      OpenSSL/3.0
53        udp   open           dns          90% (banner)
9200      tcp   open           unknown      -
```
`nmap` = Nmap's own probe/signature match confidence; `banner` = identified from live response content via signature matching (e.g. an `SSH-` prefix, an HTTP status line, a validated DNS/NTP/SNMP reply). If a port gives no live evidence at all, it stays `unknown` rather than being labeled from a hardcoded port-number table. The same fields (`confidence`, `confidence_source`) are included in JSON output via `-o`.

### 15. OS Fingerprinting Summary (Requires Root)
When Nmap's OS detection runs (needs `CAP_NET_RAW`/root — see example 8 for granting it without `sudo`), the highest-accuracy match is parsed and shown per host:
```bash
sudo target/release/netenum 192.168.1.50 -p 22,80,443 --i-have-authorization
```
```text
Results for 192.168.1.50:
OS: Linux 4.15 - 5.6 (98% accuracy)
PORT      PROTO STATE          SERVICE      CONFIDENCE      VERSION/BANNER
22        tcp   open           ssh          70% (nmap)      OpenSSH 9.6
```
Without root, Nmap enrichment still runs (service/version detection) but OS detection is skipped, so no `OS:` line appears. The same data is available as `os: { name, accuracy }` on each host in JSON output via `-o`.

### 16. Restrict Scanning to an Approved Scope
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
