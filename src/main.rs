#![feature(panic_info_message)]

mod scan_network;
mod scan_ports;

use std::net::Ipv4Addr;

use anyhow::{Error, Result};
use clap::error::ErrorKind;
use crate::scan_network::scan_network;
use clap::Parser;
use crate::scan_ports::scan_ports;

/// A simple network scanner CLI tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The network range to scan (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    network: Option<String>,

    /// A single IP address to scan
    #[arg(short = 'i', long)]
    ip: Option<Ipv4Addr>,

    /// A range of IP addresses to scan (e.g., 192.168.1.1-192.168.1.10)
    #[arg(short = 'r', long)]
    range: Option<String>,

    /// The interface to use
    #[arg(short = 'I', long)]
    interface: Option<String>,

    /// The port to scan
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// The ports to scan
    #[arg(short = 'P', long = "pN")]
    ports: Option<String>,

    /// The range of ports to scan
    #[arg(short = 'R', long = "pR")]
    port_range: Option<String>,
}

fn parse_ports(ports: &str) -> Vec<u16> {
    let port_parts: Vec<&str> = ports.split(',').collect();
    let mut ports: Vec<u16> = Vec::new();
    for port in port_parts {
        let port_num: u16 = match port.parse() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("Invalid port number: {}", port);
                return Vec::new();
            }
        };
        ports.push(port_num);
    }
    ports
}

fn parse_port_range(port_range: &str) -> Vec<u16> {
    let port_parts: Vec<&str> = port_range.split('-').collect();
    if port_parts.len() != 2 {
        eprintln!("Invalid port range format. Please use format like \"1-10\".");
        return Vec::new();
    }
    let start_port: u16 = match port_parts[0].parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Invalid start port number: {}", port_parts[0]);
            return Vec::new();
        }
    };
    let end_port: u16 = match port_parts[1].parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Invalid end port number: {}", port_parts[1]);
            return Vec::new();
        }
    };
    (start_port..=end_port).collect()
}

fn parse_cidr(network: &str) -> Vec<Ipv4Addr> {
    let cidr_parts: Vec<&str> = network.split('/').collect();
    if cidr_parts.len() != 2 {
        eprintln!("Invalid network range format. Please use CIDR notation (e.g., 192.168.1.0/24).");
        return Vec::new();
    }

    let base_ip: Ipv4Addr = match cidr_parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid IP address format.");
            return Vec::new();
        }
    };
    let prefix_len: u32 = match cidr_parts[1].parse() {
        Ok(len) => len,
        Err(_) => {
            eprintln!("Invalid prefix length.");
            return Vec::new();
        }
    };

    let num_hosts = 2u32.pow(32 - prefix_len);
    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for i in 1..num_hosts - 1 {
        let ip = Ipv4Addr::from(u32::from(base_ip) + i);
        ips.push(ip);
    }

    ips
}

fn parse_ip_range(range: &str) -> Vec<Ipv4Addr> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        eprintln!("Invalid IP range format. Please use format like \"192.168.1.1-192.168.1.10\".");
        return Vec::new();
    }

    let start_ip: Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid start IP address format.");
            return Vec::new();
        }
    };
    let end_ip: Ipv4Addr = match parts[1].parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid end IP address format.");
            return Vec::new();
        }
    };

    let start = u32::from(start_ip);
    let end = u32::from(end_ip);
    if start > end {
        eprintln!("Start IP address must be less than or equal to end IP address.");
        return Vec::new();
    }

    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for ip in start..=end {
        ips.push(Ipv4Addr::from(ip));
    }

    ips
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let ips = if let Some(network) = args.network {
        parse_cidr(&network)
    } else if let Some(ip) = args.ip {
        vec![ip]
    } else if let Some(range) = args.range {
        parse_ip_range(&range)
    } else {
        return Err(Error::from(clap::Error::raw(
            ErrorKind::TooFewValues,
            "Please specify a network, an IP, or a range to scan.",
        )));
    };

    let mut all_ports = Vec::new();

    if let Some(port) = args.port {
        all_ports.push(port);
    }

    if let Some(port_range) = args.port_range {
        all_ports.extend(parse_port_range(&port_range));
    }

    if let Some(ports) = args.ports {
        all_ports.extend(parse_ports(&ports));
    }

    if all_ports.is_empty() {
        match scan_network(ips, args.interface).await {
            Ok(results) => {
                println!("Scan complete. Results:");
                for (ip, mac, hostname) in results {
                    println!("IP: {} MAC: {} Hostname: {}", ip, mac, hostname);
                }
            }
            Err(e) => eprintln!("Error during scan: {:?}", e),
        }
    } else if ips.len() == 1 {
        let results = scan_ports(ips[0], &all_ports).await;
        println!("Scan complete. Results:");
        for port in results {
            println!("Port: {}", port);
        }
    } else {
        return Err(Error::from(clap::Error::raw(
            ErrorKind::TooManyValues,
            "To Many IPs to scan ports on! please only provide one IP to scan ports on using the `-i` flag or the `--ip` flag.",
        )));
    }


    Ok(())
}
