extern crate etherparse;

use std::cmp;

use crate::errors::RustTcpError;
use crate::packets::{
    build_ack_packet, build_fin_packet, build_push_ack_packet, build_reset_packet,
    build_syn_ack_packet, build_syn_packet,
};
use crate::rusttcp::Connection;
use etherparse::TcpHeader;
use log::debug;
use log::error;
use log::info;

/// Represents internal events used within the TCP layer for managing state and transitions.
///
/// # Variants
///
/// - `NoEvent`: Indicates that no new internal event has occurred. This is the default state when
///   there is no action required or progress to report internally.
///
/// - `DataToSend(usize)`: Signals that there is data ready to be sent on the TCP connection.
///   - The inner `usize` represents the number of bytes that are ready for transmission.
///
/// - `DataReceivedAndAckToSend(usize, usize)`: Indicates that data has been received and acknowledged,
///   and the acknowledgment needs to be sent to the remote endpoint.
///   - The first `usize` represents the number of bytes received.
///   - The second `usize` represents the number of bytes that have been acknowledged, which will be sent
///     back to the remote endpoint to confirm receipt.
///
/// - `ConnectionClosingAndAckToSend(usize)`: Notifies that the remote endpoint has initiated a connection close,
///   and the acknowledgment for the closing segment is ready to be sent.
///   - The inner `usize` represents the number of bytes involved in the acknowledgment of the connection closing.
///
/// - `ConnectionClosed`: Indicates that the TCP connection has been fully closed, either gracefully or due to an error.
///   - No further communication can occur once this event is triggered.
pub(crate) enum InternalTcpEvent {
    NoEvent,
    DataToSend(usize),
    DataReceivedAndAckToSend(usize, usize),
    ConnectionClosingAndAckToSend(usize),
    ConnectionClosed,
}

// Represents the result of a write or retransmission operation.
//
// The `WritePacket` enum is used to indicate whether the operation has completed
// all data transmission or if more packets are pending.
//
// # Variants
// - `LastPacket(usize)`: Indicates the final packet in the sequence, with the number of bytes written.
// - `Packet(usize)`: Indicates a partial write, with more packets pending; contains the number of bytes written.
#[derive(Debug)]
pub(crate) enum WritePacket {
    LastPacket(usize),
    Packet(usize),
}

// Represents the various states of a TCP connection.
//
// The `TcpState` enum defines the states in the TCP connection lifecycle as per the TCP state machine.
//
// # Variants
// - `Closed`: Indicates that the connection is closed and not active.
// - `Listen`: Indicates that the connection is waiting for incoming SYN packets to establish a connection.
// - `SynSent`: The connection has sent a SYN packet and is waiting for a SYN-ACK from the remote endpoint.
// - `SynReceived`: The connection has received a SYN and sent a SYN-ACK in response.
// - `Established`: The connection is fully established and ready for data transfer.
// - `CloseWait`: The connection is waiting to send the final FIN after receiving a FIN from the peer.
// - `LastAck`: The connection has sent a FIN and is waiting for an acknowledgment from the peer.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
enum TcpState {
    #[default]
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
}

// Holds the context for managing the TCP receive buffer and window.
#[derive(Debug, Default, Clone)]
struct TcpRecvContext {
    isa: u32,
    next: u32,
    window_size: u16,
}

// Holds the context for managing the TCP send buffer and window.
#[derive(Debug, Default, Clone)]
struct TcpSendContext {
    isa: u32,
    next: u32,
    acked: u32,
    window_size: u16,
    buf: Vec<u8>,
    packets_index: Vec<usize>,
}

// Represents the Transmission Control Block (TCB) for a TCP connection.
//
// The `TcpTlb` struct stores the state and context required to manage a TCP connection,
// including its current state, associated connection details, and buffers for sending
// and receiving data.
#[derive(Debug, Default, Clone)]
pub(crate) struct TcpTlb {
    state: TcpState,
    connection: Connection,
    recv_buf: Vec<u8>,
    recv: TcpRecvContext,
    send: TcpSendContext,
}

impl TcpTlb {
    // Creates a new `TcpTlb` (Transmission Control Block) instance for a TCP connection.
    pub(crate) fn new(connection: Connection, window_size: u16, isa: u32) -> Self {
        TcpTlb {
            connection,
            recv: TcpRecvContext {
                window_size,
                ..Default::default()
            },
            send: TcpSendContext {
                isa,
                next: isa + 1,
                acked: isa + 1,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // Processes an incoming TCP packet and updates the connection's state and buffers.
    //
    // This method handles TCP packets based on the current state of the connection, including:
    // - Establishing new connections (e.g., SYN, SYN-ACK).
    // - Processing data and acknowledgments in an established connection.
    // - Handling connection termination (e.g., FIN, RST).
    //
    // Depending on the packet type and connection state, this method may generate a response
    // packet and return a corresponding TCP event.
    pub(crate) fn on_packet(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<InternalTcpEvent, RustTcpError> {
        info!("state = {:?}", &self.state);

        match self.state {
            TcpState::Listen => self.on_listen_state(tcphdr, payload, response),
            TcpState::SynSent => self.on_syn_sent_state(tcphdr, payload, response),
            TcpState::SynReceived => self.on_syn_received_state(tcphdr, payload, response),
            TcpState::Established => self.on_established_state(tcphdr, payload, response),
            TcpState::CloseWait => Ok(InternalTcpEvent::NoEvent),
            TcpState::LastAck => self.on_last_ack_state(tcphdr),
            TcpState::Closed => {
                let n = build_reset_packet(self.connection, tcphdr, payload.len(), response)?;
                Ok(InternalTcpEvent::DataToSend(n))
            }
        }
    }

    fn on_listen_state(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<InternalTcpEvent, RustTcpError> {
        if !tcphdr.syn {
            error!("Not a SYN packet");
            let n = build_reset_packet(self.connection, tcphdr, payload.len(), response)?;
            return Ok(InternalTcpEvent::DataToSend(n));
        }

        self.recv.isa = tcphdr.sequence_number;
        self.recv.next = self.recv.isa + 1;
        self.state = TcpState::SynReceived;

        let n = build_syn_ack_packet(
            self.connection,
            self.send.isa,
            self.recv.next,
            self.recv.window_size,
            response,
        )?;

        Ok(InternalTcpEvent::DataToSend(n))
    }

    fn on_syn_sent_state(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<InternalTcpEvent, RustTcpError> {
        if !tcphdr.ack || !tcphdr.syn {
            error!("Not a SYN_ACK packet");
            let n = build_reset_packet(self.connection, tcphdr, payload.len(), response)?;
            return Ok(InternalTcpEvent::DataToSend(n));
        }

        if tcphdr.acknowledgment_number != self.send.next {
            error!("ACK num != SEND next");
            let n = build_reset_packet(self.connection, tcphdr, payload.len(), response)?;
            return Ok(InternalTcpEvent::DataToSend(n));
        }

        self.recv.isa = tcphdr.sequence_number;
        self.recv.next = self.recv.isa + 1;
        self.send.window_size = tcphdr.window_size;

        let n = build_ack_packet(
            self.connection,
            &[],
            self.send.next,
            self.recv.next,
            self.recv.window_size,
            response,
        )?;

        self.state = TcpState::Established;

        Ok(InternalTcpEvent::DataToSend(n))
    }

    fn on_syn_received_state(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<InternalTcpEvent, RustTcpError> {
        if !tcphdr.ack {
            error!("Not a ACK packet : {:?}", tcphdr);
            let n = build_reset_packet(self.connection, tcphdr, payload.len(), response)?;
            return Ok(InternalTcpEvent::DataToSend(n));
        }

        let acknum = tcphdr.acknowledgment_number;
        if acknum != self.send.next {
            error!("Unexpected Ack number : {} != {}", acknum, self.send.next);
            let n = build_reset_packet(self.connection, tcphdr, payload.len(), response)?;
            return Ok(InternalTcpEvent::DataToSend(n));
        }

        self.send.window_size = tcphdr.window_size;
        self.state = TcpState::Established;

        Ok(InternalTcpEvent::NoEvent)
    }

    fn on_established_state(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<InternalTcpEvent, RustTcpError> {
        if tcphdr.rst {
            self.state = TcpState::Closed;
            return Ok(InternalTcpEvent::ConnectionClosed);
        }

        let payload_len = payload.len() as u32;
        let seqnum_min: u64 = tcphdr.sequence_number as u64;
        let seqnum_max: u64 = tcphdr.sequence_number as u64 + payload_len as u64;

        if self.check_seqnum_range(seqnum_min, seqnum_max).is_ok() {
            let acknum = tcphdr.acknowledgment_number;
            if tcphdr.ack && (acknum != self.send.next) {
                error!("Unexpected Ack number : {} != {}", acknum, self.send.next);
                let n = build_reset_packet(self.connection, tcphdr, payload.len(), response)?;
                return Ok(InternalTcpEvent::DataToSend(n));
            }

            self.recv.next = self.recv.next.wrapping_add(payload_len);
            self.recv_buf.extend(payload.iter());
            self.recv.window_size -= payload_len as u16;
            self.send.acked = tcphdr.acknowledgment_number;

            if tcphdr.psh || self.recv.window_size == 0 {
                let n = build_ack_packet(
                    self.connection,
                    &[],
                    self.send.next,
                    self.recv.next,
                    self.recv.window_size,
                    response,
                )?;
                return Ok(InternalTcpEvent::DataReceivedAndAckToSend(payload.len(), n));
            }

            if tcphdr.fin {
                // RFC 793, p.79: FIN: "A control bit (finis) occupying one sequence number"
                self.recv.next += 1;
                self.state = TcpState::CloseWait;

                let n = build_ack_packet(
                    self.connection,
                    &[],
                    self.send.next,
                    self.recv.next,
                    self.recv.window_size,
                    response,
                )?;

                return Ok(InternalTcpEvent::ConnectionClosingAndAckToSend(n));
            }
        }

        let n = build_ack_packet(
            self.connection,
            &[],
            self.send.next,
            self.recv.next,
            self.recv.window_size,
            response,
        )?;

        Ok(InternalTcpEvent::DataToSend(n))
    }

    fn check_seqnum_range(&self, min: u64, max: u64) -> Result<(), RustTcpError> {
        let upper_bound: u64 = self.recv.next as u64 + self.recv.window_size as u64;
        let next: u64 = self.recv.next as u64;

        if min < next || min > upper_bound {
            return Err(RustTcpError::UnexpectedSeqNum);
        }

        if max < next || max > upper_bound {
            return Err(RustTcpError::UnexpectedSeqNum);
        }

        Ok(())
    }

    fn on_last_ack_state(&mut self, tcphdr: &TcpHeader) -> Result<InternalTcpEvent, RustTcpError> {
        if tcphdr.ack && !tcphdr.fin {
            self.state = TcpState::Closed;
            return Ok(InternalTcpEvent::ConnectionClosed);
        }

        Ok(InternalTcpEvent::NoEvent)
    }

    // Prepares the TCP connection to listen for incoming connections.
    // This method transitions the TCP state to `TcpState::Listen`.
    pub(crate) fn listen(&mut self) -> Result<&mut Self, RustTcpError> {
        match self.state {
            TcpState::Closed => self.state = TcpState::Listen,
            _ => panic!("Unexpected state when opening new connection"),
        }

        Ok(self)
    }

    // Handles the closing of a TCP connection.
    //
    // This method transitions the TCP state to `TcpState::LastAck` and generates a FIN packet
    // to signal the closing of the connection.
    pub fn on_close(&mut self, packet: &mut [u8]) -> Result<usize, RustTcpError> {
        debug!("on_close");

        match self.state {
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                let n = build_fin_packet(self.connection, self.send.isa, self.recv.next, packet)?;
                Ok(n)
            }
            _ => unimplemented!(),
        }
    }

    // Reads data from the receive buffer.
    pub(crate) fn on_read(&mut self, buf: &mut [u8]) -> usize {
        let n = self.recv_buf.len();
        buf[..n].clone_from_slice(&self.recv_buf);

        self.recv_buf.truncate(0);
        self.recv.window_size += n as u16;
        n
    }

    // Initiates a TCP connection by sending a SYN packet.
    //
    // This method transitions the connection to the `TcpState::SynSent` state and generates
    // a SYN packet to initiate the three-way handshake.
    pub(crate) fn on_open(&mut self, packet: &mut [u8]) -> Result<usize, RustTcpError> {
        let n = match self.state {
            TcpState::Closed => {
                let n = build_syn_packet(
                    self.connection,
                    self.send.isa,
                    self.recv.window_size,
                    packet,
                )?;
                self.state = TcpState::SynSent;
                n
            }
            _ => unimplemented!(),
        };

        Ok(n)
    }

    // Handles writing data to the TCP connection by building and sending packets.
    //
    // This method processes a buffer of outgoing data, generates the appropriate TCP packet(s),
    // and updates the connection's state to reflect the data being sent. It ensures that
    // packets respect the sending window size and supports splitting data into multiple packets
    // if necessary.
    pub(crate) fn on_write(
        &mut self,
        buf: &[u8],
        packet: &mut [u8],
    ) -> Result<WritePacket, RustTcpError> {
        if self.state != TcpState::Established {
            return Err(RustTcpError::BadTcpState);
        }

        let curr_packet_index = (self.send.next - self.send.isa) as usize - 1;

        if !buf.is_empty() {
            self.send.buf.extend_from_slice(buf);
            self.send.packets_index.push(curr_packet_index + buf.len());
        }

        let mut remain_size = self.send.packets_index.last().unwrap() - curr_packet_index;

        // Check the maximum data the receiver can receive. 'send_size' can't be more than the sending window size.
        let send_size = cmp::min(remain_size, self.send.window_size as usize);
        let last_packet_index = curr_packet_index + send_size;
        let data = &self.send.buf[curr_packet_index..last_packet_index];
        let last_buf_index = self.send.buf[curr_packet_index..].len();

        let build_packet = if last_packet_index < last_buf_index {
            build_ack_packet
        } else {
            build_push_ack_packet
        };

        let n = build_packet(
            self.connection,
            data,
            self.send.next,
            self.recv.next,
            self.recv.window_size,
            packet,
        )?;

        self.send.next = self.send.next.wrapping_add(send_size as u32);
        remain_size -= send_size;

        match remain_size {
            0 => Ok(WritePacket::LastPacket(n)),
            _ => Ok(WritePacket::Packet(n)),
        }
    }

    // Handles retransmissions on timeout for the TCP connection.
    //
    // This method is invoked when a retransmission timeout occurs. It resends the
    // unacknowledged data from the send buffer as a new TCP packet. The method calculates
    // the appropriate size for the retransmission based on the receiver's window size and
    // prepares a packet accordingly.
    pub(crate) fn on_timeout(&mut self, request: &mut [u8]) -> Result<WritePacket, RustTcpError> {
        let curr_packet_index = (self.send.acked - self.send.isa) as usize - 1;
        let remain_size = self.send.packets_index.last().unwrap() - curr_packet_index;

        // Check the maximum data the receiver can receive. 'send_size' can't be more than the sending window size.
        let send_size = cmp::min(remain_size, self.send.window_size as usize);
        let last_packet_index = curr_packet_index + send_size;
        let data = &self.send.buf[curr_packet_index..last_packet_index];

        let build_packet = if (remain_size - send_size) > 0 {
            build_ack_packet
        } else {
            build_push_ack_packet
        };

        let n = build_packet(
            self.connection,
            data,
            self.send.acked,
            self.recv.next,
            self.recv.window_size,
            request,
        )?;

        match remain_size {
            0 => Ok(WritePacket::LastPacket(n)),
            _ => Ok(WritePacket::Packet(n)),
        }
    }
}
