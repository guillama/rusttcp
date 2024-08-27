use crate::errors::RustTcpError;
use crate::packets::TcpTlb;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::net::Ipv4Addr;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Default)]
pub struct Connection {
    pub ip_src: [u8; 4],
    pub ip_dest: [u8; 4],
    pub port_src: u16,
    pub port_dest: u16,
}

impl Connection {
    pub fn new(iphdr: &Ipv4Header, tcphdr: &TcpHeader) -> Self {
        Connection {
            ip_src: iphdr.source,
            ip_dest: iphdr.destination,
            port_src: tcphdr.source_port,
            port_dest: tcphdr.destination_port,
        }
    }
}

pub enum UserEvent {
    Close(String),
}

pub struct RustTcp {
    queue: VecDeque<UserEvent>,
    src_ip: [u8; 4],
    conns: HashMap<Connection, TcpTlb>,
    conns_by_name: HashMap<String, Connection>,
    listen_ports: HashMap<u16, (String, TcpTlb)>,
}

impl RustTcp {
    pub fn new(src_ip: &Ipv4Addr) -> Self {
        RustTcp {
            queue: VecDeque::new(),
            src_ip: src_ip.octets(),
            conns: HashMap::new(),
            conns_by_name: HashMap::new(),
            listen_ports: HashMap::new(),
        }
    }

    pub fn open(&mut self, src_port: u16, name_str: &str) {
        let tlb = TcpTlb::new().open();
        let name: String = name_str.to_string();
        self.listening_ports.insert(src_port, (name, tlb));
    }

    pub fn close(&mut self, name: &str) {
        let usr_event = UserEvent::Close(name.to_string());
        self.queue.push_front(usr_event);
    }

    pub fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, RustTcpError> {
        if let Some(c) = self.conns_by_name.get(name) {
            if let Some(tlb) = self.conns.get(c) {
                return Ok(tlb.on_read(buf));
            }
        }

        Err(RustTcpError::NameNotFound(name.to_string()))
    }

    pub fn on_packet(&mut self, packet: &[u8], response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let (iphdr, tcphdr, payload) = self.check_and_parse(packet)?;

        let conn = Connection::new(&iphdr, &tcphdr);
        if let Entry::Occupied(mut e) = self.conns.entry(conn) {
            let tlb = e.get_mut();
            return tlb.on_packet(&tcphdr, payload, response);
        }

        let entry = self.listen_ports.remove(&tcphdr.destination_port);
        if let Some((conn_name, tlb)) = entry {
            let mut new_tlb: TcpTlb = tlb.with_connection(conn);
            new_tlb.on_packet(&tcphdr, payload, response)?;

            self.conns.insert(conn, new_tlb);
            self.conns_by_name.insert(conn_name, conn);

            return Ok(());
        }

        if entry.is_none() {
            // Use temporary TLB to send Reset packet
            return TcpTlb::new()
                .with_connection(conn)
                .on_packet(&tcphdr, payload, response);
        }

        Ok(())
    }

    fn check_and_parse<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<(Ipv4Header, TcpHeader, &'a [u8]), RustTcpError> {
        let packet_len = packet.len();
        if packet_len < (Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN) {
            return Err(RustTcpError::BadPacketSize(packet_len));
        }

        let (iphdr, transport_hdr) = match Ipv4Header::from_slice(packet) {
            Ok((iphdr, tcphdr)) => (iphdr, tcphdr),
            Err(_) => return Err(RustTcpError::BadIpv4Header),
        };

        self.check_ipv4(&iphdr)?;

        let (tcphdr, payload) = match TcpHeader::from_slice(transport_hdr) {
            Ok((tcphdr, payload)) => (tcphdr, payload),
            Err(_) => return Err(RustTcpError::BadTcpHeader),
        };

        Ok((iphdr, tcphdr, payload))
    }

    fn check_ipv4(&self, hdr: &Ipv4Header) -> Result<(), RustTcpError> {
        if hdr.destination != self.src_ip {
            return Err(RustTcpError::BadAddress(hdr.destination));
        }

        if hdr.protocol != IpNumber::TCP {
            return Err(RustTcpError::BadProto(hdr.protocol.into()));
        }

        Ok(())
    }

    pub fn on_user_event(&mut self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let event: Option<UserEvent> = self.queue.pop_front();
        match event {
            Some(UserEvent::Close(name)) => self.on_close(name, response)?,
            _ => return Ok(()),
        }

        Ok(())
    }

    fn on_close(&mut self, name: String, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        if let Some(c) = self.conns_by_name.get_mut(&name) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return tlb.on_close(response);
            }
        }

        Err(RustTcpError::NameNotFound(name.to_string()))
    }
}
