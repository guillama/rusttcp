use crate::errors::RustTcpError;
use crate::packets::TcpTlb;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    io,
};

#[derive(PartialEq, Eq, Hash, Clone, Copy, Default, Debug)]
pub struct Connection {
    pub src_ip: [u8; 4],
    pub dest_ip: [u8; 4],
    pub src_port: u16,
    pub dest_port: u16,
}

impl Connection {
    pub fn new(iphdr: &Ipv4Header, tcphdr: &TcpHeader) -> Self {
        Connection {
            src_ip: iphdr.source,
            dest_ip: iphdr.destination,
            src_port: tcphdr.source_port,
            dest_port: tcphdr.destination_port,
        }
    }
}

#[derive(Debug)]
pub enum RustTcpMode {
    Passive(u16),
    Active([u8; 4], u16),
}

#[derive(Debug)]
pub enum UserEvent<'a> {
    Close(&'a str),
    Open(&'a str),
    Write(&'a str, &'a [u8]),
    WriteNext(&'a str),
}

#[derive(Default)]
pub struct RustTcp<'a> {
    queue: VecDeque<UserEvent<'a>>,
    src_ip: [u8; 4],
    conns: HashMap<Connection, TcpTlb>,
    conns_by_name: HashMap<&'a str, Connection>,
    listen_ports: HashMap<u16, (&'a str, TcpTlb)>,
    default_window_size: u16,
}

impl<'a> RustTcp<'a> {
    pub fn new(src_ip: [u8; 4]) -> Self {
        RustTcp {
            src_ip,
            default_window_size: 10,
            ..Default::default()
        }
    }

    pub fn window_size(mut self, value: u16) -> Self {
        self.default_window_size = value;
        self
    }

    pub fn open(&mut self, mode: RustTcpMode, name: &'a str) -> Result<(), RustTcpError> {
        let tlb = TcpTlb::new(self.default_window_size);

        match mode {
            RustTcpMode::Passive(src_port) => {
                self.listen_ports.insert(src_port, (name, tlb.listen()?));
            }
            RustTcpMode::Active(server_ip, server_port) => {
                let c = Connection {
                    src_ip: server_ip,
                    src_port: server_port,
                    dest_ip: self.src_ip,
                    dest_port: 36000,
                };
                self.conns.insert(c, tlb.connection(c));
                self.conns_by_name.insert(name, c);

                let usr_event = UserEvent::Open(name);
                self.queue.push_front(usr_event);
            }
        }

        Ok(())
    }

    pub fn close(&mut self, name: &'a str) {
        let usr_event = UserEvent::Close(name);
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

    pub fn write(&mut self, name: &'a str, buf: &'a [u8]) -> Result<usize, RustTcpError> {
        let usr_event = UserEvent::Write(name, buf);
        self.queue.push_front(usr_event);
        Ok(0)
    }

    pub fn on_packet<T>(&mut self, packet: &[u8], response: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let (iphdr, tcphdr, payload) = self.check_and_parse(packet)?;

        let conn = Connection::new(&iphdr, &tcphdr);
        if let Entry::Occupied(mut e) = self.conns.entry(conn) {
            let tlb = e.get_mut();
            return tlb.on_packet(&tcphdr, payload, response);
        }

        let entry = self.listen_ports.remove(&tcphdr.destination_port);
        if let Some((conn_name, tlb)) = entry {
            let mut new_tlb: TcpTlb = tlb.connection(conn);
            new_tlb.on_packet(&tcphdr, payload, response)?;

            self.conns.insert(conn, new_tlb);
            self.conns_by_name.insert(conn_name, conn);

            return Ok(());
        }

        if entry.is_none() {
            // Use temporary TLB to send Reset packet
            return TcpTlb::new(0)
                .connection(conn)
                .on_packet(&tcphdr, payload, response);
        }

        Ok(())
    }

    fn check_and_parse<'pkt>(
        &self,
        packet: &'pkt [u8],
    ) -> Result<(Ipv4Header, TcpHeader, &'pkt [u8]), RustTcpError> {
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
            return Err(RustTcpError::BadIpv4Address(hdr.destination));
        }

        if hdr.protocol != IpNumber::TCP {
            return Err(RustTcpError::BadIPv4Proto(hdr.protocol.into()));
        }

        Ok(())
    }

    pub fn on_user_event<T>(&mut self, request: &mut T) -> Result<usize, RustTcpError>
    where
        T: io::Write + Sized,
    {
        let mut remain_size = 0;
        let event: Option<UserEvent> = self.queue.pop_front();

        match event {
            Some(UserEvent::Open(name)) => {
                let tlb = self.tlb_from_connection(name)?;
                tlb.send_syn(request)?;
            }
            Some(UserEvent::Close(name)) => {
                let tlb = self.tlb_from_connection(name)?;
                tlb.on_close(request)?;
            }
            Some(UserEvent::Write(name, user_buf)) => {
                let tlb = self.tlb_from_connection(name)?;
                remain_size = tlb.on_write(user_buf, request)?;

                if remain_size > 0 {
                    let event = UserEvent::WriteNext(name);
                    self.queue.push_front(event);
                }
            }
            Some(UserEvent::WriteNext(name)) => {
                let tlb = self.tlb_from_connection(name)?;
                remain_size = tlb.on_write(&[], request)?;
            }
            None => return Err(RustTcpError::ElementNotFound),
        }

        Ok(remain_size)
    }

    fn tlb_from_connection(&mut self, name: &'a str) -> Result<&mut TcpTlb, RustTcpError> {
        if let Some(c) = self.conns_by_name.get_mut(&name) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return Ok(tlb);
            }
        }

        Err(RustTcpError::NameNotFound(name.into()))
    }
}
