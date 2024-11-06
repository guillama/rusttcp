use crate::errors::RustTcpError;
use crate::packets::TcpTlb;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};

#[cfg(feature = "mocks")]
use crate::fake_timer::Timer;
#[cfg(not(feature = "mocks"))]
use crate::timer::Timer;

use std::{
    cell::Cell,
    collections::{hash_map::Entry, HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
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
    ConnectionClosing,
    ConnectionClosed,
}

#[derive(Debug)]
pub enum RustTcpMode {
    Passive(u16),
    Active([u8; 4], u16),
}

#[derive(Debug)]
pub enum UserEvent {
    Close(i32),
    Open(i32),
    Write(i32, Vec<u8>),
    WriteNext(i32),
}

#[derive(Debug, Clone)]
pub enum TimerEvent {
    Timeout(i32, Duration),
}

#[derive(Default, Debug)]
pub struct RustTcp {
    user_queue: VecDeque<UserEvent>,
    timer_queue: VecDeque<TimerEvent>,
    poll_queue: VecDeque<TcpEvent>,

    conns: HashMap<Connection, TcpTlb>,
    conns_by_fd: HashMap<i32, Connection>,
    listen_ports: HashMap<u16, (i32, TcpTlb)>,

    src_ip: [u8; 4],
    timer: Arc<Mutex<Timer>>,
    default_window_size: u16,
    default_seqnum: u32,
    tcp_retries: u32,
    tcp_max_retries: u32,
}

#[derive(Default, Debug)]
pub struct RustTcpBuilder {
    src_ip: [u8; 4],

    timer: Arc<Mutex<Timer>>,
    window_size: u16,
    sequence_number: u32,
    tcp_max_retries: u32,
}

impl RustTcpBuilder {
    pub fn new(src_ip: [u8; 4]) -> Self {
        RustTcpBuilder {
            window_size: RustTcp::DEFAULT_WINDOW_SIZE,
            src_ip,
            ..Default::default()
        }
    }

    pub fn timer(mut self, time: Arc<Mutex<Timer>>) -> Self {
        self.timer = time;
        self
    }

    pub fn window_size(mut self, value: u16) -> Self {
        self.window_size = value;
        self
    }

    pub fn sequence_number(mut self, value: u32) -> Self {
        self.sequence_number = value;
        self
    }

    pub fn tcp_max_retries(mut self, value: u32) -> Self {
        self.tcp_max_retries = value;
        self
    }

    pub fn build(self) -> RustTcp {
        RustTcp {
            src_ip: self.src_ip,
            timer: self.timer,
            default_window_size: self.window_size,
            default_seqnum: self.sequence_number,
            tcp_max_retries: self.tcp_max_retries,
            ..Default::default()
        }
    }
}

impl RustTcp {
    const TCP_RETRIES_DEFAULT: Duration = Duration::from_millis(200);
    const TCP_RETRIES_NB_DEFAULT: u32 = 15;
    const DEFAULT_AVAILABLE_PORT: u16 = 36000;
    pub const DEFAULT_WINDOW_SIZE: u16 = 1400;

    pub fn new(src_ip: [u8; 4]) -> Self {
        RustTcp {
            src_ip,
            tcp_max_retries: RustTcp::TCP_RETRIES_NB_DEFAULT,
            default_window_size: RustTcp::DEFAULT_WINDOW_SIZE,
            ..Default::default()
        }
    }

    pub fn open(&mut self, mode: RustTcpMode) -> Result<i32, RustTcpError> {
        let tlb = TcpTlb::new(self.default_window_size, self.default_seqnum);

        thread_local! {
            static FD: Cell<i32> = Cell::new(0);
        }

        let fd = FD.with(|cell| {
            let fd = cell.get();
            cell.set(fd + 1);
            fd
        });

        match mode {
            RustTcpMode::Passive(src_port) => {
                self.listen_ports.insert(src_port, (fd, tlb.listen()?));
            }
            RustTcpMode::Active(server_ip, server_port) => {
                let c = Connection {
                    src_ip: server_ip,
                    src_port: server_port,
                    dest_ip: self.src_ip,
                    dest_port: RustTcp::DEFAULT_AVAILABLE_PORT,
                };
                self.conns.insert(c, tlb.connection(c));
                self.conns_by_fd.insert(fd, c);

                let usr_event = UserEvent::Open(fd);
                self.user_queue.push_front(usr_event);
            }
        }

        Ok(fd)
    }

    pub fn close(&mut self, fd: i32) {
        let usr_event = UserEvent::Close(fd);
        self.user_queue.push_front(usr_event);
    }

    pub fn read(&mut self, fd: i32, buf: &mut [u8]) -> Result<usize, RustTcpError> {
        if let Some(c) = self.conns_by_fd.get(&fd) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return Ok(tlb.on_read(buf));
            }
        }

        Err(RustTcpError::ConnectionNotFound(fd))
    }

    pub fn write(&mut self, fd: i32, buf: &[u8]) -> Result<usize, RustTcpError> {
        if self.conns_by_fd.get(&fd).is_none() {
            return Err(RustTcpError::ConnectionNotFound(fd));
        }

        let usr_event = UserEvent::Write(fd, buf.to_vec());
        self.user_queue.push_back(usr_event);
        Ok(0)
    }

    pub fn poll(&mut self) -> Result<TcpEvent, RustTcpError> {
        Ok(self.poll_queue.pop_back().unwrap_or(TcpEvent::NoEvent))
    }

    pub fn on_packet<T>(&mut self, packet: &[u8], response: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let (iphdr, tcphdr, payload) = self.check_and_parse(packet)?;

        let conn = Connection::new(&iphdr, &tcphdr);
        if let Entry::Occupied(mut e) = self.conns.entry(conn) {
            let tlb = e.get_mut();
            let event = tlb.on_packet(&tcphdr, payload, response)?;

            match event {
                TcpEvent::ConnectionClosed => {
                    println!("REMOVE CONN");
                    self.conns.remove(&conn);
                    self.poll_queue.push_front(event);
                }
                TcpEvent::NoEvent => (),
                _ => self.poll_queue.push_front(event),
            }

            return Ok(());
        }

        let entry = self.listen_ports.remove(&tcphdr.destination_port);
        if let Some((fd, tlb)) = entry {
            let mut new_tlb: TcpTlb = tlb.connection(conn);
            new_tlb.on_packet(&tcphdr, payload, response)?;

            self.conns.insert(conn, new_tlb);
            self.conns_by_fd.insert(fd, conn);

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
            Some(UserEvent::Open(fd)) => {
                let tlb = self.tlb_from_connection(fd)?;
                tlb.send_syn(request)?;
            }
            Some(UserEvent::Close(fd)) => {
                let tlb = self.tlb_from_connection(fd)?;
                tlb.on_close(request)?;
                self.conns_by_fd.remove(&fd);
            }
            Some(UserEvent::Write(fd, user_buf)) => {
                let tlb = self.tlb_from_connection(fd)?;
                remain_size = tlb.on_write(&user_buf, request)?;

                if remain_size > 0 {
                    self.user_queue.push_front(UserEvent::WriteNext(fd));
                }

                self.timer_queue
                    .push_front(TimerEvent::Timeout(fd, RustTcp::TCP_RETRIES_DEFAULT));
            }
            Some(UserEvent::WriteNext(fd)) => {
                let tlb = self.tlb_from_connection(fd)?;
                remain_size = tlb.on_write(&[], request)?;

                self.timer_queue
                    .push_front(TimerEvent::Timeout(fd, RustTcp::TCP_RETRIES_DEFAULT));

                if remain_size > 0 {
                    self.user_queue.push_front(UserEvent::WriteNext(fd));
                }
            }
            None => return Err(RustTcpError::ElementNotFound),
        }

        Ok(remain_size)
    }

    fn tlb_from_connection(&mut self, fd: i32) -> Result<&mut TcpTlb, RustTcpError> {
        if let Some(c) = self.conns_by_fd.get_mut(&fd) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return Ok(tlb);
            }
        }

        Err(RustTcpError::ConnectionNotFound(fd))
    }

    pub fn on_timer_event<W>(&mut self, request: &mut W) -> Result<usize, RustTcpError>
    where
        W: io::Write + Sized,
    {
        let (fd, duration) =
            if let Some(TimerEvent::Timeout(n, duration)) = self.timer_queue.front() {
                (*n, *duration)
            } else {
                return Err(RustTcpError::ElementNotFound);
            };

        if self.timer.lock().unwrap().expired() < duration {
            return Ok(0);
        }

        self.timer_queue.pop_front();

        if self.tcp_retries == self.tcp_max_retries {
            if let Some(c) = self.conns_by_fd.remove(&fd) {
                self.conns.remove(&c);
            }

            return Err(RustTcpError::MaxRetransmissionsReached(self.tcp_retries));
        }

        let send_size = self.tlb_from_connection(fd)?.on_timeout(request)?;
        let new_event = TimerEvent::Timeout(fd, duration * 2);

        self.timer_queue.push_front(new_event);
        self.timer.lock().unwrap().reset();
        self.tcp_retries += 1;

        return Ok(send_size);
    }
}
