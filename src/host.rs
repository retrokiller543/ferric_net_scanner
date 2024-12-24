use crate::MAC_ADDRESS_DB;
use anyhow::anyhow;
use dns_lookup::lookup_addr;
use eui48::MacAddress as ExternMacAddress;
use libarp::interfaces::MacAddr;
use oui::OuiEntry;
use std::fmt::{Debug, Display};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: MacAddrData,
    pub hostname: String,
}

impl Host {
    pub fn new(ip: Ipv4Addr, mac: MacAddr, hostname: String) -> Self {
        Self {
            ip,
            mac: MacAddrData {
                mac_addr: mac.into(),
                vendor: None,
            },
            hostname,
        }
    }

    pub fn get_vendor(&mut self) -> anyhow::Result<()> {
        self.mac.look_up_vendor()
    }

    pub fn verbose_str(&self) -> String {
        let vendor = if let Some(vendor) = &self.mac.vendor {
            vendor
        } else {
            &OuiEntry::default()
        };
        format!(
            "IP: {}\n\tMAC: {}\n\tVendor: {{\n\t\tShortname: {},\n\t\tLongname: {},\n\t\tDescription: {}\n\t}}\n\tHostname: {}",
            self.ip, self.mac.mac_addr, vendor.name_short, vendor.clone().name_long.unwrap_or("Not Found".to_string()), vendor.clone().comment.unwrap_or("Not Found".to_string()), self.hostname
        )
    }

    pub fn verbose(&self) -> String{
        format!("IP: {}\n{:?}\nHostname: {}", self.ip, self.mac, self.hostname)
    }
}

impl Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IP: {} ({}) Hostname: {}",
            self.ip, self.mac, self.hostname
        )
    }
}

impl From<(Ipv4Addr, MacAddr, String)> for Host {
    fn from((ip, mac, hostname): (Ipv4Addr, MacAddr, String)) -> Self {
        Self {
            ip,
            mac: mac.into(),
            hostname,
        }
    }
}

impl From<Ipv4Addr> for Host {
    fn from(ip: Ipv4Addr) -> Self {
        let mut arp_client = libarp::client::ArpClient::new().expect("Failed to create ARP client");
        let mac = crate::scan_network::get_mac_for_ip(ip, &mut arp_client)
            .unwrap_or(MacAddr::new(0, 0, 0, 0, 0, 0));

        Self {
            ip,
            mac: MacAddrData {
                mac_addr: mac.into(),
                vendor: None,
            },
            hostname: lookup_addr(&IpAddr::V4(ip)).unwrap_or_else(|_| "Not found".to_string()),
        }
    }
}

impl From<MacAddr> for Host {
    fn from(mac: MacAddr) -> Self {
        let mut arp_client = libarp::client::ArpClient::new().expect("Failed to create ARP client");
        let ip = arp_client
            .mac_to_ip(mac, Some(Duration::from_millis(250)))
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        if ip == Ipv4Addr::UNSPECIFIED {
            Self {
                ip,
                mac: mac.into(),
                hostname: "Host Not found".to_string(),
            }
        } else {
            Self {
                ip,
                mac: mac.into(),
                hostname: lookup_addr(&IpAddr::V4(ip)).unwrap_or_else(|_| "Not found".to_string()),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAddrData {
    pub mac_addr: MacAddress,
    pub vendor: Option<OuiEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacAddress {
    pub mac_addr: ExternMacAddress,
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mac_addr)
    }
}

impl From<MacAddr> for MacAddress {
    fn from(mac_addr: MacAddr) -> Self {
        let mac: [u8; 6] = [
            mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3, mac_addr.4, mac_addr.5,
        ];

        Self {
            mac_addr: ExternMacAddress::new(mac),
        }
    }
}

impl From<ExternMacAddress> for MacAddress {
    fn from(mac_addr: ExternMacAddress) -> Self {
        Self { mac_addr }
    }
}

impl From<MacAddress> for ExternMacAddress {
    fn from(mac_addr: MacAddress) -> Self {
        mac_addr.mac_addr
    }
}

impl From<MacAddress> for MacAddr {
    fn from(mac_addr: MacAddress) -> Self {
        let mac_addr = mac_addr.mac_addr.as_bytes();
        Self::new(
            mac_addr[0],
            mac_addr[1],
            mac_addr[2],
            mac_addr[3],
            mac_addr[4],
            mac_addr[5],
        )
    }
}

impl MacAddrData {
    pub fn new(mac_addr: MacAddress, vendor: Option<OuiEntry>) -> Self {
        Self { mac_addr, vendor }
    }

    pub fn look_up_vendor(&mut self) -> anyhow::Result<()> {
        let oui_db = oui::OuiDatabase::new_from_str(MAC_ADDRESS_DB)
            .map_err(|e| anyhow!("Failed to parse MAC address database: {}", e))?;

        if self.vendor.is_none() {
            self.vendor = oui_db
                .query_by_mac(&self.mac_addr.mac_addr)
                .map_err(|e| anyhow!("Failed to query MAC address database: {}", e))?;
        }

        Ok(())
    }
}

impl From<MacAddr> for MacAddrData {
    fn from(mac_addr: MacAddr) -> Self {
        let mac_addr = MacAddress::from(mac_addr);
        Self {
            mac_addr,
            vendor: None,
        }
    }
}

impl Display for MacAddrData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vendor) = &self.vendor {
            write!(f, "{} ({})", self.mac_addr, vendor.name_short)
        } else {
            write!(f, "{}", self.mac_addr)
        }
    }
}

impl FromStr for MacAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(ExternMacAddress::from_str(s)?))
    }
}

impl From<MacAddrData> for MacAddr {
    fn from(mac_addr: MacAddrData) -> Self {
        let mac_addr = mac_addr.mac_addr.mac_addr.as_bytes();
        Self::new(
            mac_addr[0],
            mac_addr[1],
            mac_addr[2],
            mac_addr[3],
            mac_addr[4],
            mac_addr[5],
        )
    }
}
