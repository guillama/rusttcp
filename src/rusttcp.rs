use crate::errors::RustTcpError;
use crate::packets::build_reset_packet;
use crate::tlb::{TcpTlb, WritePacket};
use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use log::{debug, error, info};

#[cfg(feature = "mocks")]
use crate::fake_timer::Timer;
#[cfg(not(feature = "mocks"))]
use crate::timer::Timer;

use std::{
    cell::Cell,
    collections::{hash_map::Entry, HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(PartialEq, Eq, Hash, Clone, Copy, Default, Debug)]
/// Represents a connection between two processes, identified by a pair of sockets.
///
/// A socket is defined as a combination of an IP address and a port number.
/// A `Connection` struct pairs the source and destination sockets to uniquely identify
/// a communication channel between two endpoints in a network.
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
/// Represents events that can be returned to the user application by the TCP layer.
///
/// These events notify the application about significant changes or actions
/// in the TCP connection's state, excluding the `NoEvent` variant.
///
/// # Variants
///
/// - `NoEvent`: Indicates that no new event has occurred. This is the default state when
///   there is nothing to report to the application.
///
/// - `DataReceived(usize)`: Signals that new data has been received on the TCP connection.
///   - The inner `usize` represents the number of bytes received and available for processing.
///
/// - `ConnectionClosing`: Notifies that the remote endpoint has initiated a graceful connection close,
///   typically through a FIN segment. The connection is still active but will soon close.
///
/// - `ConnectionClosed`: Indicates that the TCP connection has been fully closed, either gracefully
///   or due to an error. The application can no longer send or receive data.
pub enum TcpEvent {
    NoEvent,
    DataReceived(usize),
    ConnectionClosing,
    ConnectionClosed,
}

#[derive(Debug)]
/// Represents the mode of a TCP open request, which can either be passive or active.
///
/// This enum is used to specify whether a TCP connection should be initiated actively
/// or if it should passively wait for incoming connection requests.
///
/// # Variants
///
/// - `Passive(port)`: Indicates a passive open request, where the process listens on the
///   specified port for incoming connection requests.
///
/// - `Active(ip, port)`: Represents an active open request, where the process attempts to
///   establish a connection to a remote endpoint.
///
pub enum RustTcpMode {
    /// A passive open request, where the process listens for incoming connections on the specified port.
    Passive(u16),
    /// An active open request, where the process initiates a connection to a remote endpoint.
    Active([u8; 4], u16),
}

#[derive(Debug)]
enum UserEvent {
    Close(i32),
    Open(i32),
    Write(i32, Vec<u8>),
    WriteNext(i32),
}

#[derive(Debug, Clone)]
enum TimerEvent {
    Timeout(i32, Duration),
}

#[derive(Default, Debug)]
/// Manages the state, events, and metadata of TCP connections.
///
/// The `RustTcp` struct provides comprehensive management for TCP connections,
/// including tracking events, managing timers, and maintaining metadata for active
/// and passive connections. It serves as the core structure for a TCP implementation.
///
/// # Responsibilities
///
/// - **Event Tracking**: Handles user interactions, timer-based events, and TCP-specific
///   events using dedicated queues.
/// - **Connection Management**: Maps and tracks active network connections,
///   including metadata and file descriptor associations.
/// - **Default Parameters**: Maintains default TCP parameters such as window size,
///   sequence numbers, and retry counts.
/// - **Connection Metadata**: Stores and manages data structures related to active
///   connections and listening ports.
pub struct RustTcp {
    user_queue: VecDeque<UserEvent>,
    timer_queue: VecDeque<TimerEvent>,
    poll_queue: VecDeque<TcpEvent>,

    conns: HashMap<Connection, TcpTlb>,
    conns_by_fd: HashMap<i32, Connection>,
    listen_ports: HashMap<u16, i32>,

    src_ip: [u8; 4],
    timer: Arc<Mutex<Timer>>,
    default_window_size: u16,
    default_seqnum: u32,
    tcp_retries: u32,
    tcp_max_retries: u32,
}

/// A builder for configuring and initializing a custom TCP implementation
#[derive(Default, Debug)]
pub struct RustTcpBuilder {
    src_ip: [u8; 4],

    timer: Arc<Mutex<Timer>>,
    window_size: u16,
    sequence_number: u32,
    tcp_max_retries: u32,
}

impl RustTcpBuilder {
    /// Creates a new instance of `RustTcpBuilder` with the specified source IP address.
    pub fn new(src_ip: [u8; 4]) -> Self {
        RustTcpBuilder {
            window_size: RustTcp::DEFAULT_WINDOW_SIZE,
            src_ip,
            ..Default::default()
        }
    }

    /// Sets the timer for the TCP connection.
    ///
    /// This method allows you to configure a shared timer instance, which is
    /// used to manage connection timeouts and retransmission events.
    pub fn timer(mut self, time: Arc<Mutex<Timer>>) -> Self {
        self.timer = time;
        self
    }

    /// Sets the TCP window size.
    ///
    /// The window size determines the amount of data that can be sent and
    /// unacknowledged at any given time during the TCP connection.
    pub fn window_size(mut self, value: u16) -> Self {
        self.window_size = value;
        self
    }

    /// Sets the initial sequence number for the TCP connection.
    ///
    /// This sequence number is used during the connection establishment phase
    /// to synchronize communication between endpoints.
    pub fn sequence_number(mut self, value: u32) -> Self {
        self.sequence_number = value;
        self
    }

    /// Sets the maximum number of retries for retransmitting packets.
    ///
    /// This parameter determines how many times a packet will be retransmitted
    /// before the connection is considered failed.
    pub fn tcp_max_retries(mut self, value: u32) -> Self {
        self.tcp_max_retries = value;
        self
    }

    /// Builds and returns a `RustTcp` instance with the configured parameters.
    ///
    /// This method consumes the builder and produces a `RustTcp` struct initialized
    /// with the parameters specified in the builder. Any fields not explicitly set
    /// will use their default values.
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

    /// Creates a new `RustTcp` instance with default configuration.
    pub fn new(src_ip: [u8; 4]) -> Self {
        RustTcp {
            src_ip,
            tcp_max_retries: RustTcp::TCP_RETRIES_NB_DEFAULT,
            default_window_size: RustTcp::DEFAULT_WINDOW_SIZE,
            ..Default::default()
        }
    }

    /// Opens a TCP connection in either passive or active mode.
    ///
    /// Depending on the provided `mode`, this method either:
    /// - Configures the instance to listen for incoming connections (passive mode).
    /// - Initiates an outgoing connection (active mode).
    ///
    /// # Parameters
    /// - `mode`: A `RustTcpMode` enum specifying whether to open the connection in passive
    ///   or active mode.
    ///
    /// # Returns
    /// - `Ok(i32)`: The file descriptor (`fd`) assigned to the connection on success.
    /// - `Err(RustTcpError)`: An error if the connection cannot be opened.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    ///
    /// // Passive mode example
    /// let fd = tcp.open(RustTcpMode::Passive(8080)).unwrap();
    ///
    /// // Active mode example
    /// let fd = tcp.open(RustTcpMode::Active([192, 168, 1, 100], 80)).unwrap();
    /// ```
    pub fn open(&mut self, mode: RustTcpMode) -> Result<i32, RustTcpError> {
        info!("OPEN");

        thread_local! {
            static FD: Cell<i32> = const { Cell::new(0) };
        }

        let fd = FD.with(|cell| {
            let fd = cell.get();
            cell.set(fd + 1);
            fd
        });

        match mode {
            RustTcpMode::Passive(src_port) => {
                info!("Server listening on port {src_port}...");
                self.listen_ports.insert(src_port, fd);
            }
            RustTcpMode::Active(server_ip, server_port) => {
                let conn = Connection {
                    src_ip: server_ip,
                    src_port: server_port,
                    dest_ip: self.src_ip,
                    dest_port: RustTcp::DEFAULT_AVAILABLE_PORT,
                };
                let tlb = TcpTlb::new(conn, self.default_window_size, self.default_seqnum);
                self.conns.insert(conn, tlb);
                self.conns_by_fd.insert(fd, conn);
                self.user_queue.push_front(UserEvent::Open(fd));
            }
        }

        Ok(fd)
    }

    /// Closes an existing TCP connection.
    ///
    /// # Parameters
    /// - `fd`: An `i32` representing the file descriptor of the connection to close.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    /// let fd = tcp.open(RustTcpMode::Passive(8080)).unwrap();
    ///
    /// tcp.close(fd);
    /// ```
    pub fn close(&mut self, fd: i32) {
        info!("CLOSE");
        self.user_queue.push_front(UserEvent::Close(fd));
    }

    /// Reads data from a TCP connection associated with the specified file descriptor.
    ///
    /// # Parameters
    /// - `fd`: An `i32` representing the file descriptor of the connection to read from.
    /// - `buf`: A mutable slice where the read data will be stored.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes read on success.
    /// - `Err(RustTcpError)`: An error if the file descriptor is not associated with an active connection.
    ///
    /// # Errors
    /// - Returns `RustTcpError::ConnectionNotFound(fd)` if the file descriptor does not map to any active connection.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    /// let fd = tcp.open(RustTcpMode::Passive(8080)).unwrap();
    ///
    /// let mut buffer = [0u8; 1024];
    /// match tcp.read(fd, &mut buffer) {
    ///     Ok(bytes_read) => println!("Read {} bytes", bytes_read),
    ///     Err(e) => println!("Failed to read: {:?}", e),
    /// }
    /// ```
    pub fn read(&mut self, fd: i32, buf: &mut [u8]) -> Result<usize, RustTcpError> {
        info!("READ");

        if let Some(c) = self.conns_by_fd.get(&fd) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return Ok(tlb.on_read(buf));
            }
        }

        Err(RustTcpError::ConnectionNotFound(fd))
    }

    /// Writes data to a TCP connection associated with the specified file descriptor.
    ///
    /// # Parameters
    /// - `fd`: An `i32` representing the file descriptor of the connection to write to.
    /// - `buf`: A slice containing the data to be written.
    ///
    /// # Returns
    /// - `Ok(usize)`: Always returns `Ok(0)` to indicate the write operation was queued successfully.
    /// - `Err(RustTcpError)`: An error if the file descriptor is not associated with an active connection.
    ///
    /// # Errors
    /// - Returns `RustTcpError::ConnectionNotFound(fd)` if the file descriptor does not map to any active connection.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    /// let fd = tcp.open(RustTcpMode::Active([192, 168, 1, 100], 80)).unwrap();
    ///
    /// let data = b"Hello, server!";
    /// match tcp.write(fd, data) {
    ///     Ok(_) => println!("Write operation queued"),
    ///     Err(e) => println!("Failed to write: {:?}", e),
    /// }
    /// ```
    pub fn write(&mut self, fd: i32, buf: &[u8]) -> Result<usize, RustTcpError> {
        info!("WRITE");

        if !self.conns_by_fd.contains_key(&fd) {
            return Err(RustTcpError::ConnectionNotFound(fd));
        }

        let usr_event = UserEvent::Write(fd, buf.to_vec());
        self.user_queue.push_back(usr_event);
        Ok(0)
    }

    /// Retrieves the next event from the TCP layer.
    ///
    /// # Returns
    /// - `TcpEvent`: The next event from the queue, or `TcpEvent::NoEvent` if the queue is empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    /// let fd = tcp.open(RustTcpMode::Active([192, 168, 1, 1], 80)).unwrap();
    /// match tcp.poll() {
    ///     TcpEvent::NoEvent => println!("No events to process."),
    ///     event => println!("Processing event: {:?}", event),
    /// }
    /// ```
    pub fn poll(&mut self) -> TcpEvent {
        self.poll_queue.pop_back().unwrap_or(TcpEvent::NoEvent)
    }

    /// Processes an incoming TCP packet and generates a response if needed.
    ///
    /// This method handles a raw TCP packet, parses it, and determines the appropriate action
    /// based on the current state of the connection. It can generate a response packet
    /// and queue events for further processing.
    ///
    /// # Parameters
    /// - `packet`: A byte slice containing the incoming TCP packet.
    /// - `response`: A mutable byte slice where the response packet will be written, if applicable.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written to the `response` buffer.
    /// - `Err(RustTcpError)`: An error if the packet is invalid or processing fails.
    ///
    /// # Behavior
    /// - Parses the packet into its IP header, TCP header, and payload.
    /// - Checks if the connection already exists:
    ///   - If the connection exists, it processes the packet within the connection's context.
    /// - If the packet is for a listening port, it initiates a new connection.
    /// - If no matching connection or listener is found, a TCP reset packet is generated as a response.
    ///
    /// # Errors
    /// - Returns `RustTcpError` if the packet is invalid or an unexpected error occurs during processing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    /// let fd = tcp.open(RustTcpMode::Passive(80)).unwrap();
    ///
    /// let incoming_packet = [/* raw TCP packet data */];
    /// let mut response = [0u8; 1500];
    ///
    /// match tcp.on_packet(&incoming_packet, &mut response) {
    ///     Ok(bytes_written) => println!("Response generated with {} bytes", bytes_written),
    ///     Err(e) => println!("Failed to process packet: {:?}", e),
    /// }
    /// ```
    pub fn on_packet(&mut self, packet: &[u8], response: &mut [u8]) -> Result<usize, RustTcpError> {
        let (iphdr, tcphdr, payload) = self.check_and_parse(packet)?;

        let conn = Connection::new(&iphdr, &tcphdr);
        if let Entry::Occupied(mut e) = self.conns.entry(conn) {
            debug!("Connection already establihed");
            let tlb = e.get_mut();
            let (event, n) = tlb.on_packet(&tcphdr, payload, response)?;

            match event {
                TcpEvent::ConnectionClosed => {
                    debug!("Remove connection");
                    self.conns.remove(&conn);
                    self.poll_queue.push_front(event);
                }
                TcpEvent::NoEvent => (),
                _ => self.poll_queue.push_front(event),
            }

            return Ok(n);
        }

        let entry = self.listen_ports.remove(&tcphdr.destination_port);
        if let Some(fd) = entry {
            info!("Connection accepted on port {}", tcphdr.destination_port);

            let mut tlb = TcpTlb::new(conn, self.default_window_size, self.default_seqnum);
            let (_, n) = tlb.listen()?.on_packet(&tcphdr, payload, response)?;
            self.conns.insert(conn, tlb);
            self.conns_by_fd.insert(fd, conn);

            return Ok(n);
        }

        if entry.is_none() {
            error!("Connection not found: {:?}, {:?}", conn, &self.conns_by_fd);
            let n = build_reset_packet(conn, &tcphdr, payload.len(), response)?;
            return Ok(n);
        }

        Ok(0)
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

    /// Processes user-initiated events and generates the corresponding TCP packets.
    ///
    /// This method handles events from the `user_queue`, such as opening connections,
    /// closing connections, or writing data. Based on the type of event, it interacts
    /// with the appropriate `TcpTlb` (Transmission Control Block) and generates TCP packets
    /// to be sent to the network.
    ///
    /// # Parameters
    /// - `request`: A mutable byte slice where the generated TCP packet will be written.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written to the `request` buffer on success.
    /// - `Err(RustTcpError)`: An error if no event is found in the queue or processing fails.
    ///
    /// # Errors
    /// - Returns `RustTcpError::ElementNotFound` if no event is present in the `user_queue`.
    /// - Returns other `RustTcpError` variants if processing the event fails (e.g., due to invalid file descriptors).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    /// let fd = tcp.open(RustTcpMode::Passive(80)).unwrap();
    ///
    /// let mut buffer = [0u8; 1500];
    /// match tcp.on_user_event(&mut buffer) {
    ///     Ok(bytes_written) => println!("Generated {} bytes of TCP packet", bytes_written),
    ///     Err(e) => println!("Failed to process user event: {:?}", e),
    /// }
    /// ```
    pub fn on_user_event(&mut self, request: &mut [u8]) -> Result<usize, RustTcpError> {
        let event: Option<UserEvent> = self.user_queue.pop_front();
        let n = match event {
            Some(UserEvent::Open(fd)) => {
                let tlb = self.tlb_from_connection(fd)?;
                tlb.send_syn(request)?
            }
            Some(UserEvent::Close(fd)) => {
                let tlb = self.tlb_from_connection(fd)?;
                let n = tlb.on_close(request)?;
                self.conns_by_fd.remove(&fd);
                n
            }
            Some(UserEvent::Write(fd, user_buf)) => {
                self.timer_queue
                    .push_front(TimerEvent::Timeout(fd, RustTcp::TCP_RETRIES_DEFAULT));

                let tlb = self.tlb_from_connection(fd)?;
                match tlb.on_write(&user_buf, request)? {
                    WritePacket::Packet(n) => {
                        self.user_queue.push_front(UserEvent::WriteNext(fd));
                        n
                    }
                    WritePacket::LastPacket(n) => n,
                }
            }
            Some(UserEvent::WriteNext(fd)) => {
                self.timer_queue
                    .push_front(TimerEvent::Timeout(fd, RustTcp::TCP_RETRIES_DEFAULT));

                let tlb = self.tlb_from_connection(fd)?;
                match tlb.on_write(&[], request)? {
                    WritePacket::Packet(n) => {
                        self.user_queue.push_front(UserEvent::WriteNext(fd));
                        n
                    }
                    WritePacket::LastPacket(n) => n,
                }
            }
            None => return Err(RustTcpError::ElementNotFound),
        };

        Ok(n)
    }

    fn tlb_from_connection(&mut self, fd: i32) -> Result<&mut TcpTlb, RustTcpError> {
        if let Some(c) = self.conns_by_fd.get_mut(&fd) {
            if let Some(tlb) = self.conns.get_mut(c) {
                return Ok(tlb);
            }
        }

        Err(RustTcpError::ConnectionNotFound(fd))
    }

    /// Handles a timer event, typically triggered for retransmission or timeout management.
    ///
    /// # Parameters
    /// - `request`: A mutable byte slice where the generated TCP packet will be written.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written to the `request` buffer on success.
    /// - `Err(RustTcpError)`: An error if no timer event is found, or the maximum number of retransmissions is reached.
    ///
    /// # Errors
    /// - Returns `RustTcpError::ElementNotFound` if no timer event is found.
    /// - Returns `RustTcpError::MaxRetransmissionsReached` if the retry limit is exceeded.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusttcp::rusttcp::*;
    ///
    /// let mut tcp = RustTcp::new([192, 168, 1, 1]);
    /// let fd = tcp.open(RustTcpMode::Passive(80)).unwrap();
    ///
    /// // Assume a timer event is already queued
    /// let mut buffer = [0u8; 1500];
    /// match tcp.on_timer_event(&mut buffer) {
    ///     Ok(bytes_written) => println!("Handled timer event, generated {} bytes", bytes_written),
    ///     Err(e) => println!("Failed to handle timer event: {:?}", e),
    /// }
    /// ```
    pub fn on_timer_event(&mut self, request: &mut [u8]) -> Result<usize, RustTcpError> {
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
                debug!("Remove connection");
                self.conns.remove(&c);
            }

            return Err(RustTcpError::MaxRetransmissionsReached(self.tcp_retries));
        }

        let n = match self.tlb_from_connection(fd)?.on_timeout(request)? {
            WritePacket::Packet(n) => {
                self.user_queue.push_front(UserEvent::WriteNext(fd));
                n
            }
            WritePacket::LastPacket(n) => n,
        };
        let new_event = TimerEvent::Timeout(fd, duration * 2);

        self.timer_queue.push_front(new_event);
        self.timer.lock().unwrap().reset();
        self.tcp_retries += 1;

        Ok(n)
    }
}
