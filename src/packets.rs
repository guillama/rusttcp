extern crate etherparse;

use std::cmp;
use std::io;

use crate::connection::{Connection, TcpEvent};
use crate::errors::RustTcpError;
use etherparse::{PacketBuilder, TcpHeader};

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

    pub fn on_packet<T>(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut T,
    ) -> Result<TcpEvent, RustTcpError>
    where
        T: io::Write + Sized,
    {
        let mut event: TcpEvent = TcpEvent::NoEvent;

        match self.state {
            TcpState::Closed => {
                self.send_reset_packet(tcphdr, payload.len(), response)?;
            }
            TcpState::Listen => {
                if !tcphdr.syn {
                    return self.send_reset_packet(tcphdr, payload.len(), response);
                }

                self.recv.isa = tcphdr.sequence_number;
                self.recv.next = self.recv.isa + 1;
                self.send_syn_ack_packet(response)?;
                self.state = TcpState::SynReceived;
            }
            TcpState::SynSent => {
                if !tcphdr.ack || !tcphdr.syn {
                    return self.send_reset_packet(tcphdr, payload.len(), response);
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    self.send_reset_packet(tcphdr, payload.len(), response)?;
                }

                self.recv.isa = tcphdr.sequence_number;
                self.recv.next = self.recv.isa + 1;
                self.send.window_size = tcphdr.window_size;

                self.build_ack_packet(&[], self.send.next, response)?;
                self.state = TcpState::Established;
            }
            TcpState::SynReceived => {
                if !tcphdr.ack {
                    return self.send_reset_packet(tcphdr, payload.len(), response);
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    self.send_reset_packet(tcphdr, payload.len(), response)?;
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
                    return Ok(TcpEvent::ConnectionClosed);
                }

                if self.check_seqnum_range(seqnum_min, seqnum_max).is_ok() {
                    self.recv.next = self.recv.next.wrapping_add(payload_len);
                    self.recv_buf.extend(payload.iter());
                    self.recv.window_size -= payload_len as u16;

                    if tcphdr.psh || self.recv.window_size == 0 {
                        event = TcpEvent::DataReceived(payload.len());
                    }

                    if tcphdr.ack && (tcphdr.acknowledgment_number >= self.send.next) {
                        self.send.acked = tcphdr.acknowledgment_number;
                    }

                    if tcphdr.fin {
                        // RFC 793, p.79: FIN: "A control bit (finis) occupying one sequence number"
                        self.recv.next += 1;

                        self.state = TcpState::CloseWait;
                        event = TcpEvent::ConnectionClosing;
                    }
                }

                self.build_ack_packet(&[], self.send.next, response)?;
            }
            TcpState::CloseWait => {}
            TcpState::LastAck => {
                if tcphdr.ack && !tcphdr.fin {
                    self.state = TcpState::Closed;
                    event = TcpEvent::ConnectionClosed;
                }
            }
        }

        Ok(event)
    }

    fn send_reset_packet<T>(
        &self,
        tcphdr: &TcpHeader,
        payload_len: usize,
        response: &mut T,
    ) -> Result<TcpEvent, RustTcpError>
    where
        T: io::Write + Sized,
    {
        let seqnum = match tcphdr.ack {
            true => tcphdr.acknowledgment_number,
            false => 0,
        };

        PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.dest_port,
                self.connection.src_port,
                seqnum,
                self.recv.window_size,
            )
            .rst()
            .ack(tcphdr.sequence_number + payload_len as u32)
            .write(response, &[])?;

        Ok(TcpEvent::NoEvent)
    }

    fn send_syn_ack_packet<T>(&mut self, response: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let server_ip = self.connection.dest_ip;
        let server_port = self.connection.dest_port;
        let client_ip = self.connection.src_ip;
        let client_port = self.connection.src_port;

        PacketBuilder::ipv4(server_ip, client_ip, 64)
            .tcp(
                server_port,
                client_port,
                self.send.isa,
                self.recv.window_size,
            )
            .syn()
            .ack(self.recv.next)
            .write(response, &[])?;

        Ok(())
    }

    fn build_ack_packet<T>(
        &self,
        data: &[u8],
        seqnum: u32,
        request: &mut T,
    ) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(client_port, server_port, seqnum, self.recv.window_size)
            .ack(self.recv.next)
            .write(request, data)?;

        Ok(())
    }

    fn build_push_ack_packet<T>(
        &self,
        data: &[u8],
        seqnum: u32,
        request: &mut T,
    ) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(client_port, server_port, seqnum, self.recv.window_size)
            .ack(self.recv.next)
            .psh()
            .write(request, data)?;

        Ok(())
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

    pub fn send_syn<T>(&mut self, request: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        match self.state {
            TcpState::Closed => {
                self.build_syn_packet(request)?;
                self.state = TcpState::SynSent;
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn build_syn_packet<T>(&mut self, request: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(
                client_port,
                server_port,
                self.send.isa,
                self.recv.window_size,
            )
            .syn()
            .write(request, &[])?;

        Ok(())
    }

    pub fn on_close<T>(&mut self, request: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        match self.state {
            TcpState::CloseWait => {
                self.build_fin_packet(request)?;
                self.state = TcpState::LastAck;
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn build_fin_packet<T>(&self, response: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.dest_port,
                self.connection.src_port,
                self.send.isa,
                self.recv.window_size,
            )
            .ack(self.recv.next)
            .fin()
            .write(response, &[])?;

        Ok(())
    }

    pub fn on_read(&mut self, buf: &mut [u8]) -> usize {
        let n = self.recv_buf.len();
        buf[..n].clone_from_slice(&self.recv_buf);

        self.recv_buf.truncate(0);
        self.recv.window_size += n as u16;

        n
    }

    pub fn on_write<T>(&mut self, buf: &[u8], request: &mut T) -> Result<usize, RustTcpError>
    where
        T: io::Write + Sized,
    {
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

        if last_packet_index < last_buf_index {
            self.build_ack_packet(packet, self.send.next, request)?;
        } else {
            self.build_push_ack_packet(packet, self.send.next, request)?;
        }

        self.send.next = self.send.next.wrapping_add(send_size as u32);
        remain_size -= send_size;

        //todo!("pop last index if remain size is equal to 0");
        Ok(remain_size)
    }

    pub fn on_timeout<T>(&mut self, request: &mut T) -> Result<usize, RustTcpError>
    where
        T: io::Write + Sized,
    {
        let curr_packet_index = (self.send.acked - self.send.isa) as usize - 1;
        let remain_size = self.send.packets_index.last().unwrap() - curr_packet_index;

        // Check the maximum data the receiver can receive. 'send_size' can't be more than the sending window size.
        let send_size = cmp::min(remain_size, self.send.window_size as usize);
        let last_packet_index = curr_packet_index + send_size;
        let packet = &self.send.buf[curr_packet_index..last_packet_index];

        if (remain_size - send_size) > 0 {
            self.build_ack_packet(packet, self.send.acked, request)?;
        } else {
            self.build_push_ack_packet(packet, self.send.acked, request)?;
        }

        Ok(remain_size)
    }
}
