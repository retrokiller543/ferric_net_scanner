use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::task;
use std::sync::{Arc, Mutex};

pub async fn scan_ports(ip: Ipv4Addr, ports: &[u16]) -> Vec<u16> {
    let mut tasks = Vec::new();
    println!("Please note that currently not all ports get found inside the range even if we try them all sadly");
    let mut ports = ports.to_vec();

    ports.sort();
    ports.dedup();

    dbg!(&ports[ports.len() - 1]);

    let pb = ProgressBar::new(ports.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}").unwrap()
        .progress_chars("##-"));

    // Wrap the progress bar in a Arc and Mutex to share safely across threads
    let pb = Arc::new(Mutex::new(pb));

    for port in ports {
        let pb = Arc::clone(&pb); // Clone the Arc to obtain a new reference for the thread
        let socket_addr = SocketAddr::new(IpAddr::V4(ip), port);
        let task = task::spawn(async move {
            if let Ok(Ok(_)) = timeout(Duration::from_secs(3), TcpStream::connect(&socket_addr)).await {
                let mut pb = pb.lock().unwrap(); // Lock the Mutex to access the progress bar
                pb.inc(1);
                drop(pb); // Explicitly drop the lock
                Some(port)
            } else {
                let mut pb = pb.lock().unwrap();
                pb.inc(1);
                drop(pb);
                None
            }
        });
        tasks.push(task);
    }

    let mut open_ports = Vec::new();
    for task in tasks {
        if let Ok(Some(port)) = task.await {
            open_ports.push(port);
        }
    }

    let mut pb = pb.lock().unwrap();
    pb.finish_with_message("Port Scan done!");

    open_ports
}