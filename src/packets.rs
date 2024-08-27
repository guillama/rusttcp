extern crate etherparse;

use crate::connection::Connection;
use crate::errors::RustTcpError;
use etherparse::{PacketBuilder, TcpHeader};

#[derive(Clone, Debug)]
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

    pub fn on_packet(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), RustTcpError> {
        match self.state {
            TcpState::Closed => {
                return self.send_reset(tcphdr, payload.len(), response);
            }
            TcpState::Listen => {
                if !tcphdr.syn {
                    return self.send_reset(tcphdr, payload.len(), response);
                }

                self.recv.isa = tcphdr.sequence_number;
                self.recv.next = self.recv.isa + 1;
                self.send_syn_ack_packet(response)?;
                self.state = TcpState::SynReceived;
            }
            TcpState::SynSent => {
                if !tcphdr.ack {
                    return self.send_reset(tcphdr, payload.len(), response);
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    self.send_reset(tcphdr, payload.len(), response)?;
                }

                self.build_ack_packet(response)?;
                self.state = TcpState::Established;
            }
            TcpState::SynReceived => {
                if !tcphdr.ack {
                    return self.send_reset(tcphdr, payload.len(), response);
                }

                if tcphdr.acknowledgment_number != self.send.next {
                    self.send_reset(tcphdr, payload.len(), response)?;
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

                self.on_data_packet(response)?;

                if tcphdr.fin {
                    self.state = TcpState::CloseWait;
                }
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn send_reset(
        &self,
        tcphdr: &TcpHeader,
        payload_len: usize,
        response: &mut Vec<u8>,
    ) -> Result<(), RustTcpError> {
        let seqnum = match tcphdr.ack {
            true => tcphdr.acknowledgment_number,
            false => 0,
        };

        let writer = PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.src_port,
                self.connection.dest_port,
                seqnum,
                self.send.window,
            )
            .rst()
            .ack(tcphdr.sequence_number + payload_len as u32)
            .write(response, &[]);

        if writer.is_err() {
            return Err(RustTcpError::Internal);
        }

        Ok(())
    }

    fn send_syn_ack_packet(&mut self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let server_ip = self.connection.dest_ip;
        let server_port = self.connection.dest_port;
        let client_ip = self.connection.src_ip;
        let client_port = self.connection.src_port;

        let writer = PacketBuilder::ipv4(server_ip, client_ip, 64)
            .tcp(server_port, client_port, self.send.isa, self.send.window)
            .syn()
            .ack(self.recv.next)
            .write(response, &[]);

        if writer.is_err() {
            return Err(RustTcpError::Internal);
        }

        Ok(())
    }

    fn on_data_packet(&mut self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let writer = PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.src_port,
                self.connection.dest_port,
                self.send.isa,
                self.send.window,
            )
            .ack(self.recv.next)
            .write(response, &[]);

        if writer.is_err() {
            return Err(RustTcpError::Internal);
        }

        Ok(())
    }

    fn build_ack_packet(&mut self, request: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        let writer = PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(client_port, server_port, self.send.isa, self.send.window)
            .ack(self.recv.next)
            .write(request, &[]);

        if writer.is_err() {
            return Err(RustTcpError::Internal);
        }

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

    pub fn send_syn(&mut self, request: &mut Vec<u8>) -> Result<(), RustTcpError> {
        match self.state {
            TcpState::Closed => {
                self.build_syn_packet(request)?;
                self.state = TcpState::SynSent;
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn build_syn_packet(&mut self, request: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let server_ip = self.connection.src_ip;
        let server_port = self.connection.src_port;
        let client_ip = self.connection.dest_ip;
        let client_port = self.connection.dest_port;

        let writer = PacketBuilder::ipv4(client_ip, server_ip, 64)
            .tcp(client_port, server_port, self.send.isa, self.send.window)
            .syn()
            .write(request, &[]);

        if writer.is_err() {
            return Err(RustTcpError::Internal);
        }

        Ok(())
    }

    pub fn on_close(&mut self, request: &mut Vec<u8>) -> Result<(), RustTcpError> {
        match self.state {
            TcpState::CloseWait => {
                self.build_fin_packet(request)?;
                self.state = TcpState::LastAck;
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn build_fin_packet(&self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let writer = PacketBuilder::ipv4(self.connection.dest_ip, self.connection.src_ip, 64)
            .tcp(
                self.connection.src_port,
                self.connection.dest_port,
                self.send.isa,
                self.send.window,
            )
            .ack(self.recv.next)
            .fin()
            .write(response, &[]);

        if writer.is_err() {
            return Err(RustTcpError::Internal);
        }

        Ok(())
    }

    pub fn on_read(&self, buf: &mut [u8]) -> usize {
        let n = self.recv_buf.len();
        buf[0..n].clone_from_slice(&self.recv_buf);
        n
    }
}
