mod trait_impls;

use std::collections::{BTreeSet, HashMap};
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Result};

use csnmp::{ObjectIdentifier, ObjectValue, Snmp2cClient};
use libarp::interfaces::MacAddr;
use crate::host::{Host, MacAddrData, MacAddress};
use crate::scan_network::{get_ip_for_mac, scan_network};

pub struct SnmpDevice {
    snmp2c_client: Option<Snmp2cClient>,
    timeout: Option<Duration>,
    bind_addr: Option<SocketAddr>,
    pub socket_addr: SocketAddr,
    pub community: String,
    pub name: String,
    pub description: String,
    pub uptime: String,
    pub contact: String,
    pub neighbors: HashMap<String, (String, String)>, // Neighbor IP -> (MAC, Interface)
    pub interfaces: HashMap<i32, (String, String)>,   // Interface Index -> (IP, Description)
    pub arp_table: Vec<Host>
}

impl SnmpDevice {
    pub fn new(ip: Ipv4Addr, port: u16, community: String, timeout: Option<Duration>, bind_addr: Option<SocketAddr>) -> Self {
        let socket_addr: SocketAddr = SocketAddr::new(IpAddr::V4(ip), port);
        Self {
            socket_addr,
            timeout,
            bind_addr,
            community,
            ..Default::default()
        }
    }

    pub async fn create_client(&mut self) -> Result<()> {
        self.snmp2c_client = Some(Snmp2cClient::new(self.socket_addr, self.community.clone().into_bytes(), self.bind_addr, self.timeout, 3).await?);
        Ok(())
    }

    async fn get_snmp_value(&mut self, oid: ObjectIdentifier) -> Result<ObjectValue> {
        if self.snmp2c_client.is_none() {
            self.create_client().await?;
        }

        let client = self.snmp2c_client.as_mut().unwrap();

        // Perform the SNMP GET request
        let response = client.walk_bulk(oid, 10).await?;

        for (_oid, value) in response {
            return Ok(value);
        }

        Err(anyhow!("No value found for OID {:?}", oid))
    }

    pub async fn get_name(&mut self) -> Result<()> {
        // OID for sysName (1.3.6.1.2.1.1.5.0)
        let top_oid: ObjectIdentifier = "1.3.6.1.2.1.1.5.0".parse().expect("failed to parse OID");
        match self.get_snmp_value(top_oid).await? {
            ObjectValue::String(name) => {
                self.name = String::from_utf8_lossy(&name).to_string();
                Ok(())
            },
            _ => Err(anyhow!("Unexpected response type for top OID {:?}", top_oid)),
        }
    }

    pub async fn get_description(&mut self) -> Result<()> {
        // OID for sysDescr (1.3.6.1.2.1.1.1.0)
        let top_oid: ObjectIdentifier = "1.3.6.1.2.1.1.1.0".parse().expect("failed to parse OID");
        match self.get_snmp_value(top_oid).await? {
            ObjectValue::String(description) => {
                self.description = String::from_utf8_lossy(&description).to_string();
                Ok(())
            },
            _ => Err(anyhow!("Unexpected response type for OID {:?}", top_oid)),
        }
    }

    pub async fn get_uptime(&mut self) -> Result<()> {
        // OID for sysUpTime (1.3.6.1.2.1.1.3.0)
        let oid: ObjectIdentifier = "1.3.6.1.2.1.1.3.0".parse().expect("failed to parse OID");
        match self.get_snmp_value(oid).await? {
            ObjectValue::TimeTicks(uptime) => {
                self.uptime = format!("{} timeticks", uptime);
                Ok(())
            },
            _ => Err(anyhow!("Unexpected response type for OID {:?}", oid)),
        }
    }

    pub async fn get_contact(&mut self) -> Result<()> {
        // OID for sysContact (1.3.6.1.2.1.1.4.0)
        let oid: ObjectIdentifier = "1.3.6.1.2.1.1.4.0".parse().expect("failed to parse OID");
        match self.get_snmp_value(oid).await? {
            ObjectValue::String(contact) => {
                self.contact = String::from_utf8_lossy(&contact).to_string();
                Ok(())
            },
            _ => Err(anyhow!("Unexpected response type for OID {:?}", oid)),
        }
    }

    pub async fn get_neighbors_lldp(&mut self) -> Result<()> {
        let oid_sys_name: ObjectIdentifier = "1.0.8802.1.1.2.1.3.7.1.3".parse().expect("failed to parse OID");
        let oid_port_desc: ObjectIdentifier = "1.0.8802.1.1.2.1.4.1.1.7".parse().expect("failed to parse OID");

        if self.snmp2c_client.is_none() {
            self.create_client().await?;
        }

        let client = self.snmp2c_client.as_mut().unwrap();
        let sys_name_response = client.walk_bulk(oid_sys_name, 10).await?;
        let port_desc_response = client.walk_bulk(oid_port_desc, 10).await?;

        for ((_sys_name_oid, sys_name_val), (_port_desc_oid, port_desc_val)) in sys_name_response.iter().zip(port_desc_response.iter()) {
            if let ObjectValue::String(sys_name) = sys_name_val {
                if let ObjectValue::String(port_desc) = port_desc_val {
                    let neighbor_name = String::from_utf8_lossy(&sys_name).to_string();
                    let neighbor_port = String::from_utf8_lossy(&port_desc).to_string();
                    self.neighbors.insert(neighbor_name, (neighbor_port, "LLDP".to_string()));
                }
            }
        }

        Ok(())
    }

    pub async fn get_neighbors_cdp(&mut self) -> Result<()> {
        let oid_device_id: ObjectIdentifier = "1.3.6.1.4.1.9.9.23.1.2.1.1.6".parse().expect("failed to parse OID");
        let oid_device_port: ObjectIdentifier = "1.3.6.1.4.1.9.9.23.1.2.1.1.7".parse().expect("failed to parse OID");

        if self.snmp2c_client.is_none() {
            self.create_client().await?;
        }

        let client = self.snmp2c_client.as_mut().unwrap();
        let device_id_response = client.walk_bulk(oid_device_id, 10).await?;
        let device_port_response = client.walk_bulk(oid_device_port, 10).await?;

        for ((_device_id_oid, device_id_val), (_device_port_oid, device_port_val)) in device_id_response.iter().zip(device_port_response.iter()) {
            if let ObjectValue::String(device_id) = device_id_val {
                if let ObjectValue::String(device_port) = device_port_val {
                    let neighbor_name = String::from_utf8_lossy(&device_id).to_string();
                    let neighbor_port = String::from_utf8_lossy(&device_port).to_string();
                    self.neighbors.insert(neighbor_name, (neighbor_port, "CDP".to_string()));
                }
            }
        }

        Ok(())
    }

    pub async fn get_neighbors_arp(&mut self) -> Result<()> {
        let oid_arp_ip_addr: ObjectIdentifier = "1.3.6.1.2.1.4.22.1.3".parse().expect("failed to parse OID");
        let oid_arp_phys_addr: ObjectIdentifier = "1.3.6.1.2.1.4.22.1.2".parse().expect("failed to parse OID");
        let oid_arp_if_index: ObjectIdentifier = "1.3.6.1.2.1.4.22.1.1".parse().expect("failed to parse OID");

        if self.snmp2c_client.is_none() {
            self.create_client().await?;
        }

        let client = self.snmp2c_client.as_mut().unwrap();
        let arp_ip_response = client.walk_bulk(oid_arp_ip_addr, 10).await?;
        let arp_phys_response = client.walk_bulk(oid_arp_phys_addr, 10).await?;
        let arp_if_index_response = client.walk_bulk(oid_arp_if_index, 10).await?;

        for (((arp_if_oid, arp_if_val), (arp_ip_oid, arp_ip_val)), (_arp_phys_oid, arp_phys_val)) in arp_if_index_response.iter().zip(arp_ip_response.iter()).zip(arp_phys_response.iter()) {
            if let ObjectValue::Integer(if_index) = arp_if_val {
                if let ObjectValue::IpAddress(ip_addr) = arp_ip_val {
                    if let ObjectValue::String(mac_addr) = arp_phys_val {
                        let neighbor_ip = format!("{}", ip_addr);
                        let neighbor_mac = mac_addr.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(":");

                        if let Some((interface_ip, interface_descr)) = self.interfaces.get(if_index) {
                            self.neighbors.insert(neighbor_ip, (neighbor_mac, interface_descr.clone()));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn get_neighbors(&mut self) -> Result<()> {
        // Get connected interface details first
        self.get_interface_details().await?;

        if self.get_neighbors_lldp().await.is_ok() {
            return Ok(());
        }

        if self.get_neighbors_cdp().await.is_ok() {
            return Ok(());
        }

        if self.get_neighbors_arp().await.is_ok() {
            return Ok(());
        }

        Err(anyhow::anyhow!("No neighbors found"))
    }

    pub async fn get_interface_details(&mut self) -> Result<()> {
        let oid_if_index: ObjectIdentifier = "1.3.6.1.2.1.2.2.1.1".parse().expect("failed to parse OID");
        let oid_if_descr: ObjectIdentifier = "1.3.6.1.2.1.2.2.1.2".parse().expect("failed to parse OID");
        let oid_if_oper_status: ObjectIdentifier = "1.3.6.1.2.1.2.2.1.8".parse().expect("failed to parse OID");
        let oid_ip_addr: ObjectIdentifier = "1.3.6.1.2.1.4.20.1.2".parse().expect("failed to parse OID");
        let oid_ip_ad_ent_addr: ObjectIdentifier = "1.3.6.1.2.1.4.20.1.1".parse().expect("failed to parse OID");

        if self.snmp2c_client.is_none() {
            self.create_client().await?;
        }

        let client = self.snmp2c_client.as_mut().unwrap();

        let if_index_response = client.walk_bulk(oid_if_index, 10).await?;
        let if_descr_response = client.walk_bulk(oid_if_descr, 10).await?;
        let if_oper_status_response = client.walk_bulk(oid_if_oper_status, 10).await?;
        let ip_addr_response = client.walk_bulk(oid_ip_addr, 10).await?;
        let ip_ad_ent_addr_response = client.walk_bulk(oid_ip_ad_ent_addr, 10).await?;

        // Clear previous interface data
        self.interfaces.clear();

        // Collect interface descriptions and statuses
        let mut if_descriptions = HashMap::new();
        for (if_descr_oid, if_descr_val) in if_descr_response.iter() {
            if let ObjectValue::String(descr) = if_descr_val {
                if let Some(index) = if_descr_oid.to_string().split('.').last().and_then(|s| s.parse::<i32>().ok()) {
                    if_descriptions.insert(index, String::from_utf8_lossy(descr).to_string());
                }
            }
        }

        // Collect interface IP addresses
        let mut if_ips = HashMap::new();
        for (ip_addr_oid, ip_addr_val) in ip_addr_response.iter() {
            if let ObjectValue::Integer(index) = ip_addr_val {
                let oid_parts: Vec<u8> = ip_addr_oid.to_string()
                    .split('.')
                    .map(|s| s.parse::<u8>().unwrap())
                    .collect();

                // Extract the last four segments as the IP address
                if oid_parts.len() >= 4 {
                    let ip_parts = &oid_parts[oid_parts.len() - 4..];
                    let ip = format!("{}.{}.{}.{}", ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]);
                    if_ips.insert(*index, ip);
                }
            }
        }

        // Combine interface details
        for (if_index_oid, if_index_val) in if_index_response.iter() {
            if let ObjectValue::Integer(index) = if_index_val {
                if let Some(ip) = if_ips.get(index) {
                    if let Some(descr) = if_descriptions.get(index) {
                        if let Some((_oper_status_oid, oper_status_val)) = if_oper_status_response.iter().find(|(oid, _)| oid.to_string().ends_with(&format!(".{}", index))) {
                            if let ObjectValue::Integer(status) = oper_status_val {
                                if *status == 1 { // 'up'
                                    self.interfaces.insert(*index, (ip.clone(), descr.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn get_neighbor_custom(&mut self) -> Result<()> {
        let oid_net_info: ObjectIdentifier = ".1.3.6.1.4.1.8072.1.3.2.3.1.2.12.110.101.116.119.111.114.107.95.105.110.102.111".parse().expect("failed to parse OID");

        if self.snmp2c_client.is_none() {
            self.create_client().await?;
        }

        let client = self.snmp2c_client.as_mut().unwrap();
        let arp_response = client.walk_bulk(oid_net_info, 10).await?;


        // Collect interface descriptions and statuses
        for (_arp_oid, arp_val) in arp_response.iter() {
            if let ObjectValue::String(arp) = arp_val {
                let str = String::from_utf8_lossy(arp).to_string();
                let lines = str.lines().collect::<Vec<&str>>();

                for line in lines {
                    let parts = line.split(',').collect::<Vec<&str>>();
                    let interface = parts[0];
                    let mac_address = parts[1].replace(" ", "");

                    let mac_addr: MacAddress = mac_address.parse()?;

                    let mut arp_client = libarp::client::ArpClient::new().expect("Failed to create ARP client");
                    let ip = get_ip_for_mac(mac_addr.into())?;

                    self.neighbors.insert(ip.to_string(), (mac_address.to_string(), interface.to_string()));
                }

            }
        }

        Ok(())
    }

    pub async fn get_arp_table_scan(&mut self) -> Result<()> {
        // OIDs for IP addresses and subnet masks
        let oid_ip_addr: ObjectIdentifier = "1.3.6.1.2.1.4.20.1.1".parse().expect("failed to parse OID");
        let oid_subnet_mask: ObjectIdentifier = "1.3.6.1.2.1.4.20.1.3".parse().expect("failed to parse OID");

        if self.snmp2c_client.is_none() {
            self.create_client().await?;
        }

        let client = self.snmp2c_client.as_mut().unwrap();

        // Fetch all IP addresses and subnet masks
        let ip_addr_response = client.walk_bulk(oid_ip_addr, 10).await?;
        let subnet_mask_response = client.walk_bulk(oid_subnet_mask, 10).await?;

        // Extract the IP addresses and subnet masks
        let mut ip_addresses = HashMap::new();
        for (ip_oid, ip_val) in ip_addr_response.iter() {
            if let ObjectValue::IpAddress(ip) = ip_val {
                // Extract the index from the OID
                if let Some(index) = ip_oid.to_string().split('.').last().and_then(|s| s.parse::<i32>().ok()) {
                    ip_addresses.insert(index, ip);
                }
            }
        }

        let mut subnet_masks = HashMap::new();
        for (mask_oid, mask_val) in subnet_mask_response.iter() {
            if let ObjectValue::IpAddress(mask) = mask_val {
                // Extract the index from the OID
                if let Some(index) = mask_oid.to_string().split('.').last().and_then(|s| s.parse::<i32>().ok()) {
                    subnet_masks.insert(index, mask);
                }
            }
        }

        // Determine the correct network information using the SNMP server's socket address
        let mut base_address: Option<Ipv4Addr> = None;
        let mut subnet_mask: Option<Ipv4Addr> = None;
        let server_ip = if let IpAddr::V4(ip) = self.socket_addr.ip() {
            ip
        } else {
            return Err(anyhow!("SNMP server's IP address is not IPv4"));
        };

        for (index, ip) in ip_addresses.iter() {
            if ip == &&server_ip {
                if let Some(mask) = subnet_masks.get(index) {
                    base_address = Some(**ip);
                    subnet_mask = Some(**mask);
                    break;
                }
            }
        }

        if base_address.is_none() || subnet_mask.is_none() {
            return Err(anyhow!("Failed to match network information with SNMP server's socket address"));
        }

        let base_address = base_address.unwrap();
        let subnet_mask = subnet_mask.unwrap();

        dbg!(&base_address, &subnet_mask);

        // Calculate the range of IP addresses to scan
        let base_ip: u32 = u32::from(base_address);
        let mask: u32 = u32::from(subnet_mask);
        let network_address = base_ip & mask;
        let broadcast_address = network_address | !mask;
        let num_addresses = broadcast_address - network_address + 1;

        // Generate the list of IP addresses to scan
        let mut ips = Vec::new();
        for i in 0..num_addresses {
            ips.push(Ipv4Addr::from(network_address + i));
        }

        // Scan the network
        let arp_table = scan_network(ips, None).await?;
        self.set_arp_table(arp_table);

        Ok(())
    }


    pub async fn get_all(&mut self, /*tmp value of arp_table*/ arp_table: Vec<Host>) -> Result<()> {
        //self.get_arp_table_scan().await?;
        self.get_interface_details().await?;
        //self.set_arp_table(arp_table);
        if self.get_neighbor_custom().await.is_err() {
            self.get_neighbors().await?;
        }
        self.get_uptime().await?;
        self.get_contact().await?;
        self.get_name().await?;
        self.get_description().await?;

        Ok(())
    }

    pub fn set_arp_table(&mut self, arp_table: Vec<Host>) {
        self.arp_table = arp_table;
    }
}

