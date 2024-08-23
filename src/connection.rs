use crate::errors::RustTcpError;
use crate::packets::TcpTlb;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::net::Ipv4Addr;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Connection {
    pub ip_src: [u8; 4],
    pub ip_dest: [u8; 4],
    pub port_src: u16,
    pub port_dest: u16,
}

#[allow(dead_code)]
pub enum UserEvent {
    Close(String),
}

pub struct RustTcp {
    queue: VecDeque<UserEvent>,
    server_ip: Ipv4Addr,
    conns: HashMap<Connection, TcpTlb>,
    conns_by_name: HashMap<String, Connection>,
    listening_ports: HashMap<u16, String>,
}

impl RustTcp {
    pub fn new(server_ip: &Ipv4Addr) -> Self {
        RustTcp {
            queue: VecDeque::new(),
            server_ip: server_ip.clone(),
            conns: HashMap::new(),
            conns_by_name: HashMap::new(),
            listening_ports: HashMap::new(),
        }
    }

    pub fn open(&mut self, src_port: u16, name: &str) {
        self.listening_ports.insert(src_port, name.to_string());
    }

    #[allow(dead_code)]
    pub fn close(&mut self, name: &str) {
        let usr_event = UserEvent::Close(name.to_string());
        self.queue.push_front(usr_event);
    }

    pub fn on_request(
        &mut self,
        request: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), RustTcpError> {
        let request_len = request.len();

        if request_len < (Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN) {
            return Err(RustTcpError::BadPacketSize(request_len));
        }

        let (iphdr, transport_hdr) = match Ipv4Header::from_slice(&request[..request_len]) {
            Ok((iphdr, tcphdr)) => (iphdr, tcphdr),
            Err(_) => return Err(RustTcpError::BadIpv4Header),
        };

        check_ipv4(&iphdr, &self.server_ip)?;

        let (tcphdr, payload) = match TcpHeader::from_slice(transport_hdr) {
            Ok((tcphdr, payload)) => (tcphdr, payload),
            Err(_) => return Err(RustTcpError::BadTcpHeader),
        };

        let c = Connection {
            ip_src: iphdr.source,
            ip_dest: iphdr.destination,
            port_src: tcphdr.source_port,
            port_dest: tcphdr.destination_port,
        };

        if let Entry::Occupied(mut e) = self.conns.entry(c.clone()) {
            let tlb = e.get_mut();
            return tlb.on_request(&tcphdr, payload, response);
        }

        if let Some(conn_name) = self.listening_ports.remove(&tcphdr.destination_port) {
            let mut tlb = TcpTlb::new(&c);
            tlb.on_request(&tcphdr, payload, response)?;

            self.conns.insert(c.clone(), tlb.clone());
            self.conns_by_name.insert(conn_name, c.clone());

            return Ok(());
        } else {
            // Handle error
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn on_user_event(&mut self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let event: Option<UserEvent> = self.queue.pop_front();
        match event {
            Some(UserEvent::Close(name)) => self.do_close(name, response)?,
            _ => return Ok(()),
        }

        Ok(())
    }

    fn do_close(&mut self, name: String, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        if let Some(c) = self.conns_by_name.get_mut(&name) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return tlb.on_close(response);
            }
        }

        Err(RustTcpError::ElementNotFound(name.to_string()))
    }
}

fn check_ipv4(hdr: &Ipv4Header, server_ip: &Ipv4Addr) -> Result<(), RustTcpError> {
    if hdr.destination != server_ip.octets() {
        return Err(RustTcpError::BadAddress(hdr.destination));
    }

    if hdr.protocol != IpNumber::TCP {
        return Err(RustTcpError::BadProto(hdr.protocol.into()));
    }

    Ok(())
}
