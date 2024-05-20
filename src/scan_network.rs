use libarp::client::ArpClient;

use libarp::interfaces::{Interface, MacAddr};

use anyhow::{anyhow, Result};
use dns_lookup::lookup_addr;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::panic;
use std::sync::Once;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use crate::host::Host;

pub(crate) fn get_mac_for_ip(ip: Ipv4Addr, arp_client: &mut ArpClient) -> Result<MacAddr> {
    let timeout = Duration::from_millis(250);
    let result = match arp_client.ip_to_mac(ip, Some(timeout)) {
        Ok(result) => result,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::TimedOut {
                return Err(anyhow!("Timed out waiting for ARP response"));
            } else {
                panic!("Failed to send ARP request: {}", err);
            }
        }
    };
    Ok(result)
}

pub async fn scan_network(
    ips: Vec<Ipv4Addr>,
    iface: Option<String>,
) -> Result<Vec<Host>> {
    let iface = if let Some(interface) = iface {
        Interface::new_by_name(&interface).ok_or(anyhow!("Failed to find interface"))?
    } else {
        Interface::new()?
    };
    let local_ip = iface.get_ip()?;
    let pb = ProgressBar::new(ips.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")?
            .progress_chars("##-"),
    );

    let panic_flag = Arc::new(AtomicBool::new(false));
    let panic_flag_clone = Arc::clone(&panic_flag);
    let panic_printed = Arc::new(Mutex::new(false));

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let panic_printed = Arc::clone(&panic_printed);
        let panic_flag_clone = Arc::clone(&panic_flag_clone);
        panic::set_hook(Box::new(move |info| {
            let mut printed = panic_printed.lock().unwrap();
            if !*printed {
                let msg = if let Some(msg) = info.message() {
                    msg.to_string()
                } else {
                    "No message".to_string()
                };

                let location = if let Some(location) = info.location() {
                    location.to_string()
                } else {
                    "Unknown location".to_string()
                };
                eprintln!("Thread panicked: {} at {}", msg, location);
                *printed = true;
            }
            panic_flag_clone.store(true, Ordering::SeqCst);
        }));
    });

    let results: Vec<Host> = ips
        .into_par_iter()
        .filter_map(|ip| {
            if panic_flag.load(Ordering::SeqCst) {
                return None;
            }

            let mut arp_client = match ArpClient::new_with_iface(&iface) {
                Ok(client) => client,
                Err(err) => {
                    panic!("Failed to create ARP client: {}", err);
                }
            };

            pb.inc(1);

            if ip == local_ip {
                let hostname =
                    lookup_addr(&IpAddr::V4(ip)).unwrap_or_else(|_| "Not found".to_string());
                Some((ip, iface.get_mac().ok()?, hostname).into())
            } else {
                get_mac_for_ip(ip, &mut arp_client).ok().map(|mac| {
                    let hostname =
                        lookup_addr(&IpAddr::V4(ip)).unwrap_or_else(|_| "Not found".to_string());
                    (ip, mac, hostname).into()
                })
            }
        })
        .collect();

    pb.finish_with_message("Scan Complete");

    if panic_flag.load(Ordering::SeqCst) {
        return Err(anyhow!("Scan aborted due to thread panic"));
    }

    Ok(results)
}
