use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NmapRun {
    #[serde(rename = "host", default)]
    pub hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
pub struct Host {
    #[serde(rename = "address")]
    pub addresses: Vec<Address>,
    #[serde(rename = "ports", default)]
    pub ports_container: Option<PortsContainer>,
}

#[derive(Debug, Deserialize)]
pub struct Address {
    #[serde(rename = "@addr")]
    pub addr: String,
    #[serde(rename = "@addrtype")]
    pub addr_type: String,
}

#[derive(Debug, Deserialize)]
pub struct PortsContainer {
    #[serde(rename = "port", default)]
    pub ports: Vec<Port>,
}

#[derive(Debug, Deserialize)]
pub struct Port {
    #[serde(rename = "@portid")]
    pub port_id: u16,
    #[allow(dead_code)]
    #[serde(rename = "state")]
    pub state: State,
    #[serde(rename = "service")]
    pub service: Option<Service>,
    #[serde(rename = "script", default)]
    pub scripts: Vec<Script>,
}

#[derive(Debug, Deserialize)]
pub struct State {
    #[allow(dead_code)]
    #[serde(rename = "@state")]
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@product")]
    pub product: Option<String>,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "@extrainfo")]
    pub extra_info: Option<String>,
    /// Nmap's own match confidence, 0-10.
    #[serde(rename = "@conf")]
    pub conf: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct Script {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@output")]
    pub output: Option<String>,
}
