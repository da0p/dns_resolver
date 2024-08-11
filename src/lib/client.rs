use spdlog::prelude::*;
use std::{
    collections::VecDeque,
    net::{Ipv4Addr, UdpSocket},
};

use message::DnsMessage;

pub mod header;
pub mod message;
pub mod question;
pub mod rr;
pub mod utility;

/// A DNS client to query for a host name
pub struct DnsClient {
    binding_socket: UdpSocket,
}

impl DnsClient {
    /// Create a new DNS client
    pub fn new() -> DnsClient {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("Can't create socket!");

        debug!(
            "Initialize host at address: {:#?}",
            socket.local_addr().unwrap()
        );

        DnsClient {
            binding_socket: socket,
        }
    }

    /// Query a host name from a DNS server
    pub fn ask(&self, host_name: &str) {
        let mut dns_servers = VecDeque::from(self.get_root_servers());
        let mut found_ip_addrs = false;
        while !dns_servers.is_empty() {
            let dns_server = dns_servers.pop_front().unwrap();
            let (ip_addrs, _) = self.resolve_name(host_name, &dns_server);
            if ip_addrs.is_some() {
                let ip_addrs = ip_addrs.unwrap();
                println!("IP Address: \n");
                println!("[\n\t{}\n]", ip_addrs.join("\n\t"));
                found_ip_addrs = true;
                break;
            }
        }
        if !found_ip_addrs {
            error!("Can's resolve {}", host_name);
        }
    }

    /// Get all root servers address
    fn get_root_servers(&self) -> Vec<String> {
        vec![
            String::from("198.41.0.4"),     // a.root-servers.net
            String::from("199.9.14.201"),   // b.root-servers.net
            String::from("192.33.4.12"),    // c.root-servers.net
            String::from("199.7.91.13"),    // d.root-servers.net
            String::from("192.203.230.10"), // e.root-servers.net
            String::from("192.5.5.241"),    // f.root-servers.net
            String::from("198.97.190.53"),  // h.root-servers.net
            String::from("192.36.148.17"),  // i.root-servers.net
            String::from("192.58.128.30"),  // j.root-servers.net
            String::from("193.0.14.129"),   // k.root-servers.net
            String::from("199.7.83.42"),    // l.root-servers.net
            String::from("202.12.27.33"),   // m.root-servers.net
        ]
    }

    /// Resolve a host name with a root dns server
    fn resolve_name(
        &self,
        host_name: &str,
        root_dns_server: &str,
    ) -> (Option<Vec<String>>, Option<Vec<String>>) {
        let dns_question = message::DnsMessage::new(host_name);
        let mut dns_servers = VecDeque::new();
        dns_servers.push_back(root_dns_server.to_string());
        let mut ns_names = vec![];
        while !dns_servers.is_empty() {
            let dns_server = dns_servers.pop_front().unwrap();
            let conn = self.connect(&dns_server, 53);
            if conn.is_ok() {
                info!("Querying {} for {}", dns_server, host_name);
                self.send(&dns_server, 53, &dns_question.into_bytes());
                let bytes = self.listen().unwrap();
                println!("{:#2x?}", bytes);
                let dns_response = DnsMessage::parse(&bytes).unwrap();
                if dns_response.header.an_cnt > 0 {
                    let ip_addrs = dns_response
                        .answers
                        .iter()
                        .filter(|an| an.is_host_addr())
                        .map(|an| an.get_ip_addr())
                        .collect();
                    return (Some(ip_addrs), None);
                }

                if dns_response.header.ar_cnt > 0 {
                    let mut auth_servers = dns_response
                        .additionals
                        .iter()
                        .filter(|ar| ar.is_host_addr())
                        .map(|ar| ar.get_ip_addr())
                        .collect();
                    dns_servers.append(&mut auth_servers);
                } else if dns_response.header.ns_cnt > 0 {
                    ns_names = dns_response
                        .authorities
                        .iter()
                        .map(|rr| DnsMessage::decode_address(&rr.rr_name))
                        .collect();
                }
            }
        }
        if !ns_names.is_empty() {
            return (None, Some(ns_names));
        }

        (None, None)
    }

    /// Send a udp message to a remote address
    fn send(&self, remote_addr: &str, port: u16, msg: &[u8]) -> usize {
        let result: usize = 0;
        let addr = format!("{}:{}", remote_addr, port);
        match self.binding_socket.send_to(msg, addr) {
            Ok(number_of_bytes) => {
                debug!(
                    "Send a {}-byte message to address: {}:{}",
                    number_of_bytes, remote_addr, port
                );
            }
            Err(_) => error!(
                "Failed sending message: {}",
                std::str::from_utf8(msg).unwrap().to_string()
            ),
        }

        result
    }

    /// Connect to a remote address on a port
    fn connect(&self, remote_addr: &str, port: u16) -> std::io::Result<()> {
        debug!("Connecting to {}:{}", remote_addr, port);
        let addr = format!("{}:{}", remote_addr, port);
        self.binding_socket.connect(addr)
    }

    /// Listen to a response from a remote address
    fn listen(&self) -> Option<Vec<u8>> {
        let mut buffer = [0; 1024];
        match self.binding_socket.recv_from(&mut buffer) {
            Ok((number_of_bytes, _)) => {
                debug!("Received: {} bytes", number_of_bytes);
                let result = Vec::from(&buffer[0..number_of_bytes]);
                Some(result)
            }
            Err(_) => None,
        }
    }
}
