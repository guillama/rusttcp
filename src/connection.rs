use crate::errors::RustTcpError;
use crate::packets::TcpTlb;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};

#[cfg(feature = "mocks")]
use crate::fake_timer::Timer;
#[cfg(not(feature = "mocks"))]
use crate::timer::Timer;

use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap, VecDeque},
    io,
    rc::Rc,
    time::Duration,
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

#[derive(Debug, PartialEq)]
pub enum TcpEvent {
    NoEvent,
    DataReceived(usize),
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

#[derive(Debug)]
pub enum TimerEvent<'a> {
    Timeout(&'a str, Duration),
}

#[derive(Default, Debug)]
pub struct RustTcp<'a> {
    user_queue: VecDeque<UserEvent<'a>>,
    timer_queue: VecDeque<TimerEvent<'a>>,
    src_ip: [u8; 4],
    conns: HashMap<Connection, TcpTlb>,
    conns_by_name: HashMap<&'a str, Connection>,
    listen_ports: HashMap<u16, (&'a str, TcpTlb)>,
    tcp_events: Vec<TcpEvent>,
    default_window_size: u16,
    default_seqnum: u32,
    timer: Rc<RefCell<Timer>>,
}

impl<'a> RustTcp<'a> {
    pub fn new(src_ip: [u8; 4]) -> Self {
        RustTcp {
            src_ip,
            ..Default::default()
        }
    }

    pub fn timer(mut self, time: Rc<RefCell<Timer>>) -> Self {
        self.timer = time;
        self
    }

    pub fn window_size(mut self, value: u16) -> Self {
        self.default_window_size = value;
        self
    }

    pub fn sequence_number(mut self, value: u32) -> Self {
        self.default_seqnum = value;
        self
    }

    pub fn open(&mut self, mode: RustTcpMode, name: &'a str) -> Result<(), RustTcpError> {
        let tlb = TcpTlb::new(self.default_window_size, self.default_seqnum);

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
                self.user_queue.push_front(usr_event);
            }
        }

        Ok(())
    }

    pub fn close(&mut self, name: &'a str) {
        let usr_event = UserEvent::Close(name);
        self.user_queue.push_front(usr_event);
    }

    pub fn read(&mut self, name: &str, buf: &mut [u8]) -> Result<usize, RustTcpError> {
        if let Some(c) = self.conns_by_name.get(name) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return Ok(tlb.on_read(buf));
            }
        }

        Err(RustTcpError::NameNotFound(name.to_string()))
    }

    pub fn write(&mut self, name: &'a str, buf: &'a [u8]) -> Result<usize, RustTcpError> {
        let usr_event = UserEvent::Write(name, buf);
        self.user_queue.push_back(usr_event);
        Ok(0)
    }

    pub fn poll(&mut self) -> Result<TcpEvent, RustTcpError> {
        Ok(self.tcp_events.pop().unwrap_or(TcpEvent::NoEvent))
    }

    pub fn on_packet<T>(&mut self, packet: &[u8], response: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let (iphdr, tcphdr, payload) = self.check_and_parse(packet)?;

        let conn = Connection::new(&iphdr, &tcphdr);
        if let Entry::Occupied(mut e) = self.conns.entry(conn) {
            let tlb = e.get_mut();
            if let TcpEvent::DataReceived(n) = tlb.on_packet(&tcphdr, payload, response)? {
                self.tcp_events.push(TcpEvent::DataReceived(n));
            }

            return Ok(());
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
            TcpTlb::new(0, 0)
                .connection(conn)
                .on_packet(&tcphdr, payload, response)?;
            return Ok(());
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
        let event: Option<UserEvent> = self.user_queue.pop_front();

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
                    self.user_queue.push_front(UserEvent::WriteNext(name));
                }

                self.timer_queue
                    .push_front(TimerEvent::Timeout(name, Duration::from_millis(200)));
            }
            Some(UserEvent::WriteNext(name)) => {
                let tlb = self.tlb_from_connection(name)?;
                remain_size = tlb.on_write(&[], request)?;

                self.timer_queue
                    .push_front(TimerEvent::Timeout(name, Duration::from_millis(200)));

                if remain_size > 0 {
                    self.user_queue.push_front(UserEvent::WriteNext(name));
                }
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

    pub fn on_timer_event<W>(&mut self, request: &mut W) -> Result<usize, RustTcpError>
    where
        W: io::Write + Sized,
    {
        let event = self.timer_queue.pop_front();

        match event {
            Some(TimerEvent::Timeout(name, duration)) => {
                if self.timer.borrow().expired() >= duration {
                    let send_size = self.tlb_from_connection(name)?.on_timeout(request)?;

                    let new_event = TimerEvent::Timeout(name, 2 * duration);
                    self.timer.borrow_mut().reset();
                    self.timer_queue.push_front(new_event);

                    return Ok(send_size);
                } else {
                    self.timer_queue.push_front(event.unwrap());
                }
            }
            _ => return Err(RustTcpError::ElementNotFound),
        }

        Ok(0)
    }
}
