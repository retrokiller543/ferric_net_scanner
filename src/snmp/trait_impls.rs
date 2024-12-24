use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use crate::snmp::SnmpDevice;

impl Debug for SnmpDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnmpDevice")
            .field("target socket", &self.socket_addr)
            .field("community", &self.community)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("uptime", &self.uptime)
            .field("contact", &self.contact)
            .field("neighbors", &self.neighbors)
            .field("interfaces", &self.interfaces)
            .field("arp_table", &self.arp_table)
            .finish()
    }
}

impl Default for SnmpDevice {
    fn default() -> Self {
        Self {
            snmp2c_client: None,
            timeout: None,
            bind_addr: None,
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 161),
            community: String::new(),
            name: String::new(),
            description: String::new(),
            uptime: String::new(),
            contact: String::new(),
            neighbors: HashMap::new(),
            interfaces: HashMap::new(),
            arp_table: Vec::new(),
        }
    }
}