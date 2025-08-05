use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::Arc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags};
use tokio::sync::{RwLock, broadcast, mpsc};

use crate::state::workload::WorkloadChange;
use crate::state::workload::{self, InboundProtocol};

mod port_binding {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/port_binding.skel.rs"
    ));
}

#[derive(Clone, Debug)]
pub enum Command {
    AddToMesh(bool, Vec<u8>),
    RemoveFromMesh(bool, Vec<u8>),
    AddToSocket(bool, Vec<u8>, i32),
    RemoveFromSocket(bool, Vec<u8>),
    AttachToNetns(String, i32),
    DetachFromNetns(String),
}

pub struct BpfTask {
    port_binding_tx: mpsc::Sender<Command>,
    state_workload_rx: bool,
    proxy_workload_rx: bool,
    workload_data: Arc<RwLock<HashMap<String, RawFd>>>,
}

impl BpfTask {
    pub fn with_state_workload_subscriber(
        &mut self,
        subscriber: broadcast::Receiver<workload::WorkloadChange>,
    ) {
        if self.state_workload_rx {
            panic!("State workload subscriber already set");
        }
        self.state_workload_rx = true;

        let mut rx = subscriber;
        let tx = self.port_binding_tx.clone();
        let workload_data = self.workload_data.clone();
        let tx_retry: broadcast::Sender<WorkloadChange> = broadcast::Sender::new(100);
        let mut rx_retry = tx_retry.subscribe();
        tokio::spawn(async move {
            loop {
                let change = tokio::select! {
                    biased;
                    result = rx.recv() => {
                        if result.is_err() {
                            break;
                        }
                        result.unwrap()
                    }
                    result = rx_retry.recv() => {
                        if result.is_err() {
                            panic!("Retry channel closed");
                        }
                        result.unwrap()
                    }
                };
                let any_workload = match (&change.old, &change.new) {
                    (Some(old), _) => old,
                    (None, Some(new)) => new,
                    (None, None) => panic!("Both old and new workloads are None"),
                };
                if any_workload.protocol != InboundProtocol::HBONE {
                    continue;
                }
                let workload_full_name =
                    format!("{}/{}", any_workload.namespace, any_workload.name);
                let mut workload_data_guard = workload_data.write().await;
                let listener_fd = match workload_data_guard.get(&workload_full_name) {
                    Some(listener_fd) => *listener_fd,
                    None => -1,
                };

                if change.new.is_none() {
                    workload_data_guard.remove(&workload_full_name);
                }
                drop(workload_data_guard);

                let (ips_to_remove, ips_to_add, ips_to_add_addr) = compute_ip_changes(&change);
                // Send remove commands
                for ip in ips_to_remove {
                    let (ipv4, network_bytes) =
                        parse_ip_to_network_bytes(&ip).expect("Failed to parse IP address");
                    tx.send(Command::RemoveFromMesh(ipv4, network_bytes.clone()))
                        .await
                        .expect("Failed to send RemoveFromMesh command");
                    tx.send(Command::RemoveFromSocket(ipv4, network_bytes.clone()))
                        .await
                        .expect("Failed to send RemoveFromSocket command");
                }

                // Send add commands
                for ip in ips_to_add {
                    let (ipv4, network_bytes) =
                        parse_ip_to_network_bytes(&ip).expect("Failed to parse IP address");
                    tx.send(Command::AddToMesh(ipv4, network_bytes.clone()))
                        .await
                        .expect("Failed to send AddToMesh command");
                    if listener_fd != -1 {
                        tx.send(Command::AddToSocket(
                            ipv4,
                            network_bytes.clone(),
                            listener_fd,
                        ))
                        .await
                        .expect("Failed to send AddToSocket command");
                    } else {
                        eprintln!(
                            "Workload {} not found in workload_data, retrying...",
                            workload_full_name
                        );
                        // Spawn a future to retry after 2 seconds
                        let tx_retry_clone = tx_retry.clone();
                        let mut change_clone = change.clone();
                        if let Some(new_workload) = &mut change_clone.new {
                            new_workload.workload_ips = ips_to_add_addr.clone();
                        }
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            let _ = tx_retry_clone.send(change_clone);
                        });
                    }
                }
            }
        });
    }

    pub fn with_proxy_workload_subscriber(
        &mut self,
        subscriber: broadcast::Receiver<(String, i32, i32)>,
    ) {
        if self.proxy_workload_rx {
            panic!("Proxy workload subscriber already set");
        }
        self.proxy_workload_rx = true;

        let mut rx = subscriber;
        let tx = self.port_binding_tx.clone();
        let workload_data = self.workload_data.clone();
        tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                // Handle proxy workload changes
                let (uid, netns_fd, sock_fd) = msg;
                if netns_fd > -1 {
                    tx.send(Command::AttachToNetns(uid.clone(), netns_fd))
                        .await
                        .expect("Failed to send AttachToNetns command");

                    let mut workload_data_guard = workload_data.write().await;
                    if workload_data_guard.get(&uid).is_none() {
                        // Insert new workload data
                        workload_data_guard.insert(uid.clone(), sock_fd);
                        eprintln!("Workload {} added with socket fd {}", uid, sock_fd);
                    }
                } else {
                    tx.send(Command::DetachFromNetns(uid.clone()))
                        .await
                        .expect("Failed to send DetachFromNetns command");
                }
            }
        });
    }
}

pub fn init_bpf() -> anyhow::Result<BpfTask> {
    let (tx, rx) = mpsc::channel(100);
    run_port_binding(rx)?;

    Ok(BpfTask {
        port_binding_tx: tx,
        state_workload_rx: false,
        proxy_workload_rx: false,
        workload_data: Arc::new(RwLock::new(HashMap::new())),
    })
}

fn run_port_binding(mut rx: mpsc::Receiver<Command>) -> anyhow::Result<()> {
    tokio::spawn(async move {
        let result: anyhow::Result<()> = async {
            // Load the eBPF program
            let skel_builder = port_binding::PortBindingSkelBuilder::default();
            let mut open_obj = MaybeUninit::uninit();
            let open_skel = skel_builder.open(&mut open_obj)?;
            let skel = open_skel.load()?;
            let mut netns_links: HashMap<String, libbpf_rs::Link> = HashMap::new();

            while let Some(command) = rx.recv().await {
                eprintln!("Received command: {:?}", command);
                match command {
                    Command::AddToMesh(ipv4, network_bytes) => {
                        eprintln!("Adding to mesh: {:?}", network_bytes);
                        // Update eBPF maps for adding to mesh
                        if ipv4 {
                            // Handle IPv4
                            let key = &network_bytes;
                            let value = 1u8;
                            if let Err(e) =
                                skel.maps
                                    .mesh_ip4
                                    .update(key, &value.to_le_bytes(), MapFlags::ANY)
                            {
                                eprintln!("Failed to update mesh_ip4 map: {}", e);
                            }
                        }
                    }
                    Command::RemoveFromMesh(ipv4, network_bytes) => {
                        eprint!("Removing from mesh: {:?}", network_bytes);
                        // Update eBPF maps for removing from mesh
                        if ipv4 {
                            // Handle IPv4
                            let key = &network_bytes;
                            if let Err(e) = skel.maps.mesh_ip4.delete(key) {
                                eprintln!("Failed to delete from mesh_ip4 map: {}", e);
                            }
                        }
                    }
                    Command::AttachToNetns(uid, netns_fd) => {
                        // Handle netns attachment
                        let link = match skel.progs.port_binding.attach_netns(netns_fd) {
                            Ok(link) => link,
                            Err(e) => {
                                eprintln!("Failed to attach port binding: {}", e);
                                continue;
                            }
                        };
                        eprintln!("Attached to netns: {}", netns_fd);
                        // Store the link for later detachment
                        netns_links.insert(uid.clone(), link);
                    }
                    Command::DetachFromNetns(uid) => {
                        // Handle netns detachment
                        if let Some(link) = netns_links.remove(&uid) {
                            if let Err(e) = link.detach() {
                                eprintln!("Failed to detach netns: {}", e);
                            } else {
                                eprintln!("Detached from netns: {}", uid);
                            }
                        }
                    }
                    Command::AddToSocket(ipv4, network_bytes, socket_fd) => {
                        // Handle adding to socket
                        if ipv4 {
                            // Handle IPv4
                            let key = &network_bytes;
                            let value = &(socket_fd as u64).to_ne_bytes();
                            eprintln!(
                                "Adding to redir_map_ip4 map: {:?} -> {}",
                                network_bytes, socket_fd
                            );
                            if let Err(e) =
                                skel.maps.redir_map_ip4.update(key, value, MapFlags::ANY)
                            {
                                eprintln!("Failed to update redir_map_ip4 map: {}", e);
                            } else {
                                eprintln!(
                                    "Added to redir_map_ip4 map: {:?} -> {:?}",
                                    key, value
                                );
                            }
                        }
                    }
                    Command::RemoveFromSocket(ipv4, network_bytes) => {
                        // Handle removing from socket
                        if ipv4 {
                            // Handle IPv4
                            let key = &network_bytes;
                            if let Err(e) = skel.maps.redir_map_ip4.delete(key) {
                                eprintln!("Failed to delete from redir_map_ip4 map: {}", e);
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            eprintln!("Error in port binding task: {}", e);
        }
    });

    Ok(())
}

fn parse_ip_to_network_bytes(ip_str: &str) -> anyhow::Result<(bool, Vec<u8>)> {
    let ip: IpAddr = ip_str.parse()?;

    match ip {
        IpAddr::V4(ipv4) => {
            // IPv4 address as 4 bytes in network byte order (already big-endian)
            Ok((true, ipv4.octets().to_vec()))
        }
        IpAddr::V6(ipv6) => {
            // IPv6 address as 16 bytes in network byte order (already big-endian)
            Ok((false, ipv6.octets().to_vec()))
        }
    }
}

fn compute_ip_changes(
    change: &workload::WorkloadChange,
) -> (Vec<String>, Vec<String>, Vec<IpAddr>) {
    let mut remove_ips = Vec::new();
    let mut add_ips = Vec::new();
    let mut remove_ips_addr = Vec::new();
    let mut add_ips_addr = Vec::new();

    if let Some(old_workload) = &change.old {
        for ip in &old_workload.workload_ips {
            //remove_ips.push(ip.to_string());
            remove_ips_addr.push(*ip);
        }
    }

    if let Some(new_workload) = &change.new {
        for ip in &new_workload.workload_ips {
            //add_ips.push(ip.to_string());
            add_ips_addr.push(*ip);
        }
    }

    // Remove IPs that exist in both vectors
    let common_ips: std::collections::HashSet<_> = remove_ips_addr
        .iter()
        .filter(|ip| add_ips_addr.contains(ip))
        .cloned()
        .collect();

    let filtered_remove: Vec<IpAddr> = remove_ips_addr
        .into_iter()
        .filter(|ip| !common_ips.contains(ip))
        .collect();

    let filtered_add: Vec<IpAddr> = add_ips_addr
        .into_iter()
        .filter(|ip| !common_ips.contains(ip))
        .collect();

    for ip in &filtered_remove {
        remove_ips.push(ip.to_string());
    }

    for ip in &filtered_add {
        add_ips.push(ip.to_string());
    }

    (remove_ips, add_ips, filtered_add)
}
