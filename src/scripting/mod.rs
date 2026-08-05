use std::path::Path;
use mlua::Lua;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::timeout;
use std::time::Duration;
use crate::model::{ScanResultSummary, PortStatus, TransportProtocol};

// Raw helper to perform HTTP/1.0 GET request without external HTTP library dependencies
async fn http_get_raw(host: &str, port: u16, path: &str, timeout_ms: u64) -> Result<(u16, String), String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .map_err(|_| "Connection timeout")?
        .map_err(|e| e.to_string())?;

    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: netenum/0.1.0\r\nConnection: close\r\n\r\n",
        path, host
    );

    timeout(Duration::from_millis(timeout_ms), stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "Write timeout")?
        .map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    timeout(Duration::from_millis(timeout_ms), stream.read_to_end(&mut response))
        .await
        .map_err(|_| "Read timeout")?
        .map_err(|e| e.to_string())?;

    let resp_str = String::from_utf8_lossy(&response).into_owned();
    
    // Parse the status code
    let mut status = 0;
    if resp_str.starts_with("HTTP/") {
        if let Some(first_line) = resp_str.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[1].parse::<u16>() {
                    status = code;
                }
            }
        }
    }

    Ok((status, resp_str))
}

// Raw helper to connect and grab a banner
async fn tcp_connect_raw(host: &str, port: u16, payload: Option<String>, timeout_ms: u64) -> Result<String, String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .map_err(|_| "Connection timeout")?
        .map_err(|e| e.to_string())?;

    if let Some(p) = payload {
        timeout(Duration::from_millis(timeout_ms), stream.write_all(p.as_bytes()))
            .await
            .map_err(|_| "Write timeout")?
            .map_err(|e| e.to_string())?;
    }

    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf))
        .await
        .map_err(|_| "Read timeout")?
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Scans the specified directory for native `.lua` script plugins and executes them
/// against all open ports discovered during the scanning phase.
///
/// For each eligible port and script:
/// 1. Instantiates a dedicated, isolated Lua VM.
/// 2. Binds the `netenum` host APIs (`http_get`, `tcp_connect`, `log`) as async functions.
/// 3. Executes the script contents to register global functions.
/// 4. Invokes the script's `applies_to(port)` function to verify target compatibility.
/// 5. Invokes `run(host, port)` and appends any returned findings to the host's banner results.
pub async fn run_plugins(results: &mut ScanResultSummary, plugins_dir: &str) {
    let path = Path::new(plugins_dir);
    if !path.exists() || !path.is_dir() {
        return;
    }

    // Read all .lua files from the plugins directory
    let mut scripts = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let file_path = entry.path();
            if file_path.extension().map_or(false, |ext| ext == "lua") {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let name = file_path.file_name().unwrap().to_string_lossy().into_owned();
                    scripts.push((name, content));
                }
            }
        }
    }

    if scripts.is_empty() {
        return;
    }

    println!("[*] Running native Lua script plugins (loaded {} script(s))...", scripts.len());

    // Iterate hosts and open ports
    for host in &mut results.hosts {
        let host_ip = host.ip.to_string();
        for port_res in &mut host.ports {
            // These native plugins speak TCP (raw connect/HTTP GET); running them
            // against a UDP "open" port would probe an unrelated TCP service on
            // the same port number instead of the one actually scanned.
            if port_res.status != PortStatus::Open || port_res.protocol != TransportProtocol::Tcp {
                continue;
            }

            for (script_name, script_content) in &scripts {
                // Initialize a new Lua VM per script execution to ensure isolation
                let lua = Lua::new();

                // Create the netenum API module table
                let netenum = match lua.create_table() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                // Bind HTTP GET async function
                let http_get_func = lua.create_async_function(|_lua, (host, port, path, timeout_ms): (String, u16, String, Option<u64>)| async move {
                    let t_ms = timeout_ms.unwrap_or(2000);
                    match http_get_raw(&host, port, &path, t_ms).await {
                        Ok((status, body)) => {
                            let res = _lua.create_table()?;
                            res.set("status", status)?;
                            res.set("body", body)?;
                            Ok(Some(res))
                        }
                        Err(_) => Ok(None),
                    }
                });

                // Bind TCP connect async function
                let tcp_connect_func = lua.create_async_function(|_lua, (host, port, payload, timeout_ms): (String, u16, Option<String>, Option<u64>)| async move {
                    let t_ms = timeout_ms.unwrap_or(2000);
                    match tcp_connect_raw(&host, port, payload, t_ms).await {
                        Ok(banner) => Ok(Some(banner)),
                        Err(_) => Ok(None),
                    }
                });

                // Bind log function
                let s_name = script_name.clone();
                let log_func = lua.create_function(move |_lua, message: String| {
                    println!("    [{}] {}", s_name, message);
                    Ok(())
                });

                if let (Ok(h), Ok(t), Ok(l)) = (http_get_func, tcp_connect_func, log_func) {
                    let _ = netenum.set("http_get", h);
                    let _ = netenum.set("tcp_connect", t);
                    let _ = netenum.set("log", l);
                }

                if let Ok(globals) = lua.globals().set("netenum", netenum) {
                    globals
                } else {
                    continue;
                };

                // Load and execute script to populate functions
                if lua.load(script_content).exec_async().await.is_err() {
                    continue;
                }

                // Check applies_to
                let applies_to: mlua::Function = match lua.globals().get("applies_to") {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                let matches: bool = match applies_to.call_async(port_res.port).await {
                    Ok(m) => m,
                    Err(_) => false,
                };

                if !matches {
                    continue;
                }

                // Run script
                let run: mlua::Function = match lua.globals().get("run") {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                let result: Option<String> = match run.call_async((host_ip.clone(), port_res.port)).await {
                    Ok(r) => r,
                    Err(_) => None,
                };

                if let Some(finding) = result {
                    // Enrich result banner with finding
                    let old_banner = port_res.banner.take();
                    let new_banner = match old_banner {
                        Some(b) => format!("{} | {}", b, finding),
                        None => finding,
                    };
                    port_res.banner = Some(new_banner);
                }
            }
        }
    }
}
