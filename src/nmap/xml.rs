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
    #[serde(rename = "os", default)]
    pub os: Option<Os>,
}

#[derive(Debug, Deserialize)]
pub struct Os {
    #[serde(rename = "osmatch", default)]
    pub matches: Vec<OsMatch>,
}

#[derive(Debug, Deserialize)]
pub struct OsMatch {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@accuracy")]
    pub accuracy: u8,
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

#[cfg(test)]
mod tests {
    use super::*;

    // A trimmed but structurally real sample of what `nmap -O -sV -oX -` emits.
    const SAMPLE_XML: &str = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="192.168.1.50" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="9.6" conf="10"/>
</port>
</ports>
<os>
<osmatch name="Linux 4.15 - 5.6" accuracy="98" line="62606">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="98">
<cpe>cpe:/o:linux:linux_kernel:4</cpe>
</osclass>
</osmatch>
<osmatch name="Linux 5.0 - 5.4" accuracy="93" line="62607"/>
</os>
</host>
</nmaprun>"#;

    #[test]
    fn parses_os_detection_and_picks_highest_accuracy_match() {
        let run: NmapRun = quick_xml::de::from_str(SAMPLE_XML).expect("valid nmap XML must parse");
        assert_eq!(run.hosts.len(), 1);

        let os = run.hosts[0].os.as_ref().expect("<os> block must be parsed");
        assert_eq!(os.matches.len(), 2);

        let best = os.matches.iter().max_by_key(|m| m.accuracy).unwrap();
        assert_eq!(best.name, "Linux 4.15 - 5.6");
        assert_eq!(best.accuracy, 98);
    }

    #[test]
    fn missing_os_block_parses_as_none() {
        let xml = r#"<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>"#;
        let run: NmapRun = quick_xml::de::from_str(xml).expect("valid nmap XML must parse");
        assert!(run.hosts[0].os.is_none());
    }
}
