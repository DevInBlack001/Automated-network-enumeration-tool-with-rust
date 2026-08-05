use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use ipnetwork::IpNetwork;

const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;

/// Finds the local, non-loopback interface (and its own IPv4 address) whose
/// directly-connected subnet contains `target`. ARP only resolves hosts on the
/// same L2 segment, so targets outside every local interface's subnet aren't
/// eligible and should fall back to ICMP/TCP ping discovery instead.
fn find_local_interface(target: Ipv4Addr) -> Option<(NetworkInterface, Ipv4Addr)> {
    for iface in datalink::interfaces() {
        match iface.mac {
            Some(mac) if mac != MacAddr::zero() => {}
            _ => continue,
        }
        for ip_network in &iface.ips {
            if let IpNetwork::V4(v4_net) = ip_network {
                if v4_net.contains(target) {
                    return Some((iface.clone(), v4_net.ip()));
                }
            }
        }
    }
    None
}

/// Groups ARP-eligible IPv4 targets by their locally-connected interface, resolves
/// aliveness for each group with a batch of ARP requests, and returns the set of
/// targets that replied. This is a blocking call (raw AF_PACKET I/O) and must be
/// run via `tokio::task::spawn_blocking`.
pub fn arp_discover(targets: &[Ipv4Addr], timeout: Duration) -> HashSet<Ipv4Addr> {
    let mut groups: HashMap<String, (NetworkInterface, Ipv4Addr, Vec<Ipv4Addr>)> = HashMap::new();

    for &target in targets {
        if let Some((iface, src_ip)) = find_local_interface(target) {
            groups
                .entry(iface.name.clone())
                .or_insert_with(|| (iface.clone(), src_ip, Vec::new()))
                .2
                .push(target);
        }
    }

    let mut alive = HashSet::new();
    for (_, (iface, src_ip, group_targets)) in groups {
        alive.extend(probe_group(&iface, src_ip, &group_targets, timeout));
    }
    alive
}

fn probe_group(
    iface: &NetworkInterface,
    src_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Vec<Ipv4Addr> {
    let src_mac = match iface.mac {
        Some(mac) => mac,
        None => return Vec::new(),
    };

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(iface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => return Vec::new(),
    };

    for &target in targets {
        send_arp_request(&mut *tx, src_mac, src_ip, target);
    }

    let mut pending: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut found = Vec::new();
    let start = Instant::now();

    while !pending.is_empty() && start.elapsed() < timeout {
        match rx.next() {
            Ok(frame) => {
                if let Some(sender) = parse_arp_reply(frame) {
                    if pending.remove(&sender) {
                        found.push(sender);
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                continue;
            }
            Err(_) => break,
        }
    }

    found
}

fn send_arp_request(
    tx: &mut dyn datalink::DataLinkSender,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target: Ipv4Addr,
) {
    let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    let mut ethernet_packet = match MutableEthernetPacket::new(&mut ethernet_buffer) {
        Some(p) => p,
        None => return,
    };
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; ARP_PACKET_LEN];
    let mut arp_packet = match MutableArpPacket::new(&mut arp_buffer) {
        Some(p) => p,
        None => return,
    };
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target);

    ethernet_packet.set_payload(arp_packet.packet());
    let _ = tx.send_to(ethernet_packet.packet(), None);
}

/// Parses a raw Ethernet frame and returns the sender's IPv4 address if it is an ARP reply.
fn parse_arp_reply(frame: &[u8]) -> Option<Ipv4Addr> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some(arp.get_sender_proto_addr())
}
