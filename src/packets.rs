extern crate etherparse;

use std::io;

use crate::connection::Connection;
use crate::errors::RustTcpError;
use etherparse::{PacketBuilder, TcpHeader};

#[derive(Clone, Debug, PartialEq, Eq)]
enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
}

#[derive(Clone)]
struct TcpRecvContext {
    isa: u32,
    next: u32,
    window: u16,
}

#[derive(Clone)]
struct TcpSendContext {
    isa: u32,
    next: u32,
    window: u16,
}

#[derive(Clone)]
pub struct TcpTlb {
    state: TcpState,
    connection: Connection,
    recv_buf: Vec<u8>,
    recv: TcpRecvContext,
    send: TcpSendContext,
}

impl Default for TcpTlb {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpTlb {
    pub fn new() -> Self {
        TcpTlb {
            state: TcpState::Closed,
            connection: Default::default(),
            recv_buf: Vec::new(),
            recv: TcpRecvContext {
                isa: 0,
                next: 0,
                window: 10,
            },
            send: TcpSendContext {
                isa: 300,
                next: 301,
                window: 10,
            },
        }
    }

    pub fn with_connection(mut self, conn: Connection) -> Self {
        self.connection = conn;
        self.clone()
    }

    pub fn on_packet<T>(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut T,
    ) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        match self.state {
            TcpState::Closed => {
                return self.send_reset_packet(tcphdr, payload.len(), response);
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
                if !tcphdr.ack {
                    return self.send_reset_packet(tcphdr, payload.len(), response);
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    self.send_reset_packet(tcphdr, payload.len(), response)?;
                }

                self.recv.isa = tcphdr.sequence_number;
                self.recv.next = self.recv.isa + 1;
                self.build_ack_packet(&[], response)?;
                self.state = TcpState::Established;
            }
            TcpState::SynReceived => {
                if !tcphdr.ack {
                    return self.send_reset_packet(tcphdr, payload.len(), response);
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    self.send_reset_packet(tcphdr, payload.len(), response)?;
                }

                self.state = TcpState::Established;
            }
            TcpState::Established => {
                let payload_len = payload.len() as u32;
                let seqnum_min: u64 = tcphdr.sequence_number as u64;
                let seqnum_max: u64 = tcphdr.sequence_number as u64 + payload_len as u64;

                if self.check_seqnum_range(seqnum_min, seqnum_max).is_ok() {
                    self.recv.next = self.recv.next.wrapping_add(payload_len);
                    self.recv_buf.extend(payload.iter());
                }

                self.build_ack_packet(&[], response)?;

                if tcphdr.fin {
                    self.state = TcpState::CloseWait;
                }
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn send_reset_packet<T>(
        &self,
        tcphdr: &TcpHeader,
        payload_len: usize,
        response: &mut T,
    ) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let seqnum = match tcphdr.ack {
            true => tcphdr.acknowledgment_number,
            false => 0,
        };

        PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.src_port,
                self.connection.dest_port,
                seqnum,
                self.send.window,
            )
            .rst()
            .ack(tcphdr.sequence_number + payload_len as u32)
            .write(response, &[])?;

        Ok(())
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
            .tcp(server_port, client_port, self.send.isa, self.send.window)
            .syn()
            .ack(self.recv.next)
            .write(response, &[])?;

        Ok(())
    }

    fn build_ack_packet<T>(&mut self, data: &[u8], request: &mut T) -> Result<(), RustTcpError>
    where
        T: io::Write + Sized,
    {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(client_port, server_port, self.send.isa, self.send.window)
            .ack(self.recv.next)
            .write(request, data)?;

        Ok(())
    }

    fn check_seqnum_range(&self, min: u64, max: u64) -> Result<(), RustTcpError> {
        let upper_bound: u64 = self.recv.next as u64 + self.recv.window as u64 - 1;
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
            .tcp(client_port, server_port, self.send.isa, self.send.window)
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
                self.connection.src_port,
                self.connection.dest_port,
                self.send.isa,
                self.send.window,
            )
            .ack(self.recv.next)
            .fin()
            .write(response, &[])?;

        Ok(())
    }

    pub fn on_read(&self, buf: &mut [u8]) -> usize {
        let n = self.recv_buf.len();
        buf[..n].clone_from_slice(&self.recv_buf);
        n
    }

    pub fn on_write<T>(&mut self, buf: &[u8], request: &mut T) -> Result<usize, RustTcpError>
    where
        T: io::Write + Sized,
    {
        if self.state != TcpState::Established {
            return Err(RustTcpError::BadTcpState);
        }

        self.build_ack_packet(&buf, request)?;

        Ok(buf.len())
    }
}
