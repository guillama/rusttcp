extern crate etherparse;

use std::cmp;

use crate::connection::{Connection, TcpEvent};
use crate::errors::RustTcpError;
use etherparse::{PacketBuilder, TcpHeader};
use log::debug;
use log::error;
use log::info;

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

#[derive(Debug, Default, Clone)]
struct TcpRecvContext {
    isa: u32,
    next: u32,
    window_size: u16,
}

#[derive(Debug, Default, Clone)]
struct TcpSendContext {
    isa: u32,
    next: u32,
    acked: u32,
    window_size: u16,
    buf: Vec<u8>,
    packets_index: Vec<usize>,
}

#[derive(Debug, Default, Clone)]
pub struct TcpTlb {
    state: TcpState,
    connection: Connection,
    recv_buf: Vec<u8>,
    recv: TcpRecvContext,
    send: TcpSendContext,
}

impl TcpTlb {
    pub fn new(window_size: u16, isa: u32) -> Self {
        TcpTlb {
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

    pub fn connection(mut self, conn: Connection) -> Self {
        self.connection = conn;
        self.clone()
    }

    pub fn on_packet(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<(TcpEvent, usize), RustTcpError> {
        let mut event: TcpEvent = TcpEvent::NoEvent;
        let mut bytes_to_send: usize = 0;

        info!("state = {:?}", &self.state);

        match self.state {
            TcpState::Closed => {
                bytes_to_send = self.send_reset_packet(tcphdr, payload.len(), response)?;
                return Ok((TcpEvent::NoEvent, bytes_to_send));
            }
            TcpState::Listen => {
                if !tcphdr.syn {
                    error!("Not a SYN packet");
                    bytes_to_send = self.send_reset_packet(tcphdr, payload.len(), response)?;
                    return Ok((TcpEvent::NoEvent, bytes_to_send));
                }

                self.recv.isa = tcphdr.sequence_number;
                self.recv.next = self.recv.isa + 1;
                self.state = TcpState::SynReceived;

                bytes_to_send = self.build_syn_ack_packet(response)?;
            }
            TcpState::SynSent => {
                if !tcphdr.ack || !tcphdr.syn {
                    error!("Not a ACK and SYN packet");
                    bytes_to_send = self.send_reset_packet(tcphdr, payload.len(), response)?;
                    return Ok((TcpEvent::NoEvent, bytes_to_send));
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    error!("ACK num != SEND next");
                    bytes_to_send = self.send_reset_packet(tcphdr, payload.len(), response)?;
                    return Ok((TcpEvent::NoEvent, bytes_to_send));
                }

                self.recv.isa = tcphdr.sequence_number;
                self.recv.next = self.recv.isa + 1;
                self.send.window_size = tcphdr.window_size;

                bytes_to_send = self.build_ack_packet(&[], self.send.next, response)?;
                self.state = TcpState::Established;
            }
            TcpState::SynReceived => {
                if !tcphdr.ack {
                    error!("Not a ACK packet : {:?}", tcphdr);
                    bytes_to_send = self.send_reset_packet(tcphdr, payload.len(), response)?;
                    return Ok((TcpEvent::NoEvent, bytes_to_send));
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    error!(
                        "Unexpected Ack number : {} != {}",
                        tcphdr.acknowledgment_number, self.send.next
                    );
                    bytes_to_send = self.send_reset_packet(tcphdr, payload.len(), response)?;
                    return Ok((TcpEvent::NoEvent, bytes_to_send));
                }

                self.send.window_size = tcphdr.window_size;
                self.state = TcpState::Established;
            }
            TcpState::Established => {
                let payload_len = payload.len() as u32;
                let seqnum_min: u64 = tcphdr.sequence_number as u64;
                let seqnum_max: u64 = tcphdr.sequence_number as u64 + payload_len as u64;

                if tcphdr.rst {
                    self.state = TcpState::Closed;
                    return Ok((TcpEvent::ConnectionClosed, 0));
                }

                if self.check_seqnum_range(seqnum_min, seqnum_max).is_ok() {
                    self.recv.next = self.recv.next.wrapping_add(payload_len);
                    self.recv_buf.extend(payload.iter());
                    self.recv.window_size -= payload_len as u16;

                    if tcphdr.psh || self.recv.window_size == 0 {
                        event = TcpEvent::DataReceived(payload.len());
                    }

                    if tcphdr.ack && (tcphdr.acknowledgment_number != self.send.next) {
                        error!(
                            "Unexpected Ack number : {} != {}",
                            tcphdr.acknowledgment_number, self.send.next
                        );
                        bytes_to_send = self.send_reset_packet(tcphdr, payload.len(), response)?;
                        return Ok((TcpEvent::NoEvent, bytes_to_send));
                    }

                    self.send.acked = tcphdr.acknowledgment_number;

                    if tcphdr.fin {
                        // RFC 793, p.79: FIN: "A control bit (finis) occupying one sequence number"
                        self.recv.next += 1;

                        self.state = TcpState::CloseWait;
                        event = TcpEvent::ConnectionClosing;
                    }
                }

                bytes_to_send = self.build_ack_packet(&[], self.send.next, response)?;
            }
            TcpState::CloseWait => {}
            TcpState::LastAck => {
                if tcphdr.ack && !tcphdr.fin {
                    self.state = TcpState::Closed;
                    event = TcpEvent::ConnectionClosed;
                }
            }
        }

        Ok((event, bytes_to_send))
    }

    fn send_reset_packet(
        &self,
        tcphdr: &TcpHeader,
        payload_len: usize,
        response: &mut [u8],
    ) -> Result<usize, RustTcpError> {
        let seqnum = match tcphdr.ack {
            true => tcphdr.acknowledgment_number,
            false => 0,
        };

        info!("Send RESET packet with seqnum {}", seqnum);

        let mut response = &mut response[..];
        PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.dest_port,
                self.connection.src_port,
                seqnum,
                self.recv.window_size,
            )
            .rst()
            .ack(tcphdr.sequence_number.wrapping_add(payload_len as u32))
            .write(&mut response, &[])?;

        Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
    }

    fn build_syn_ack_packet(&mut self, response: &mut [u8]) -> Result<usize, RustTcpError> {
        let server_ip = self.connection.dest_ip;
        let server_port = self.connection.dest_port;
        let client_ip = self.connection.src_ip;
        let client_port = self.connection.src_port;

        let mut response = &mut response[..];
        PacketBuilder::ipv4(server_ip, client_ip, 64)
            .tcp(
                server_port,
                client_port,
                self.send.isa,
                self.recv.window_size,
            )
            .syn()
            .ack(self.recv.next)
            .write(&mut response, &[])?;

        Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
    }

    fn build_ack_packet(
        &self,
        data: &[u8],
        seqnum: u32,
        request: &mut [u8],
    ) -> Result<usize, RustTcpError> {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        let mut request = &mut request[..];
        PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(client_port, server_port, seqnum, self.recv.window_size)
            .ack(self.recv.next)
            .write(&mut request, data)?;

        Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN + data.len())
    }

    fn build_push_ack_packet(
        &self,
        data: &[u8],
        seqnum: u32,
        request: &mut [u8],
    ) -> Result<usize, RustTcpError> {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        let mut request = &mut request[..];
        PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(client_port, server_port, seqnum, self.recv.window_size)
            .ack(self.recv.next)
            .psh()
            .write(&mut request, data)?;

        Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN + data.len())
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

    pub fn listen(mut self) -> Result<Self, RustTcpError> {
        match self.state {
            TcpState::Closed => self.state = TcpState::Listen,
            _ => panic!("Unexpected state when opening new connection"),
        }

        Ok(self)
    }

    pub fn send_syn(&mut self, request: &mut [u8]) -> Result<usize, RustTcpError> {
        let n = match self.state {
            TcpState::Closed => {
                let n = self.build_syn_packet(request)?;
                self.state = TcpState::SynSent;
                n
            }
            _ => unimplemented!(),
        };

        Ok(n)
    }

    fn build_syn_packet(&mut self, request: &mut [u8]) -> Result<usize, RustTcpError> {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        let mut request = &mut request[..];
        PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(
                client_port,
                server_port,
                self.send.isa,
                self.recv.window_size,
            )
            .syn()
            .write(&mut request, &[])?;

        Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
    }

    pub fn on_close(&mut self, request: &mut [u8]) -> Result<usize, RustTcpError> {
        debug!("on_close");

        match self.state {
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                return Ok(self.build_fin_packet(request)?);
            }
            _ => unimplemented!(),
        }
    }

    fn build_fin_packet(&self, response: &mut [u8]) -> Result<usize, RustTcpError> {
        debug!("Send FIN packet");

        let mut response = &mut response[..];
        PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.dest_port,
                self.connection.src_port,
                self.send.isa,
                self.recv.window_size,
            )
            .ack(self.recv.next)
            .fin()
            .write(&mut response, &[])?;

        Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
    }

    pub fn on_read(&mut self, buf: &mut [u8]) -> usize {
        let n = self.recv_buf.len();
        buf[..n].clone_from_slice(&self.recv_buf);

        self.recv_buf.truncate(0);
        self.recv.window_size += n as u16;

        n
    }

    pub fn on_write(
        &mut self,
        buf: &[u8],
        request: &mut [u8],
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
        let packet = &self.send.buf[curr_packet_index..last_packet_index];
        let last_buf_index = self.send.buf[curr_packet_index..].len();

        let n = if last_packet_index < last_buf_index {
            self.build_ack_packet(packet, self.send.next, request)?
        } else {
            self.build_push_ack_packet(packet, self.send.next, request)?
        };

        self.send.next = self.send.next.wrapping_add(send_size as u32);
        remain_size -= send_size;

        match remain_size {
            0 => Ok(WritePacket::LastPacket(n)),
            _ => Ok(WritePacket::Packet(n)),
        }
    }

    pub fn on_timeout(&mut self, request: &mut [u8]) -> Result<WritePacket, RustTcpError> {
        let curr_packet_index = (self.send.acked - self.send.isa) as usize - 1;
        let remain_size = self.send.packets_index.last().unwrap() - curr_packet_index;

        // Check the maximum data the receiver can receive. 'send_size' can't be more than the sending window size.
        let send_size = cmp::min(remain_size, self.send.window_size as usize);
        let last_packet_index = curr_packet_index + send_size;
        let packet = &self.send.buf[curr_packet_index..last_packet_index];

        let n = if (remain_size - send_size) > 0 {
            self.build_ack_packet(packet, self.send.acked, request)?
        } else {
            self.build_push_ack_packet(packet, self.send.acked, request)?
        };

        match remain_size {
            0 => Ok(WritePacket::LastPacket(n)),
            _ => Ok(WritePacket::Packet(n)),
        }
    }
}

pub enum WritePacket {
    LastPacket(usize),
    Packet(usize),
}
