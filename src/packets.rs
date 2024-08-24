extern crate etherparse;

use crate::connection::Connection;
use crate::errors::RustTcpError;
use etherparse::{PacketBuilder, TcpHeader};

#[derive(Clone)]
enum TcpState {
    Listen,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
}

#[allow(dead_code)]
#[derive(Clone)]
struct TcpRecvContext {
    isa: u32,
    next: u32,
    window: u16,
}

#[allow(dead_code)]
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
    #[allow(dead_code)]
    recv_buf: Vec<u8>,
    recv: TcpRecvContext,
    send: TcpSendContext,
}

impl TcpTlb {
    pub fn new(connection: &Connection) -> Self {
        TcpTlb {
            state: TcpState::Listen,
            connection: connection.clone(),
            recv_buf: Vec::new(),
            recv: TcpRecvContext {
                isa: 0,
                next: 0,
                window: 10,
            },
            send: TcpSendContext {
                isa: 0,
                next: 301,
                window: 10,
            },
        }
    }

    pub fn on_request(
        &mut self,
        tcphdr: &TcpHeader,
        payload: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), RustTcpError> {
        match self.state {
            TcpState::Listen => {
                if !tcphdr.syn {
                    return Err(RustTcpError::BadState);
                }

                self.recv.isa = tcphdr.sequence_number;
                self.recv.next = self.recv.isa + 1;
                self.on_syn_request(response)?;
                self.state = TcpState::SynReceived;
            }
            TcpState::SynReceived => {
                if !tcphdr.ack {
                    return Err(RustTcpError::BadState);
                }

                self.state = TcpState::Established;
            }
            TcpState::Established => {
                let payload_len = payload.len() as u32;
                let seqnum_min = tcphdr.sequence_number;
                let seqnum_max = tcphdr.sequence_number + payload_len;

                if self.check_seqnum_range(seqnum_min, seqnum_max).is_ok() {
                    self.recv.next += payload_len;
                    self.recv_buf.extend(payload.iter());
                }

                self.on_data_request(payload, response)?;

                if tcphdr.fin {
                    self.state = TcpState::CloseWait;
                }
            }
            TcpState::CloseWait => (),
            TcpState::LastAck => unimplemented!(),
        }

        Ok(())
    }

    fn on_syn_request(&mut self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let writer = PacketBuilder::ipv4(self.connection.ip_dest, self.connection.ip_src, 64)
            .tcp(
                self.connection.port_src,
                self.connection.port_dest,
                self.send.isa,
                self.send.window,
            )
            .syn()
            .ack(self.recv.next)
            .write(response, &[]);

        if writer.is_err() {
            return Err(RustTcpError::Internal);
        }

        Ok(())
    }

    fn on_data_request(
        &mut self,
        payload: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), RustTcpError> {
        PacketBuilder::ipv4(self.connection.ip_dest, self.connection.ip_src, 64)
            .tcp(
                self.connection.port_src,
                self.connection.port_dest,
                self.send.isa,
                self.send.window,
            )
            .ack(self.recv.next)
            .write(response, &[])
            .expect("Builder failed");

        Ok(())
    }

    fn check_seqnum_range(&self, min: u32, max: u32) -> Result<(), RustTcpError> {
        let upper_bound: u32 = self.recv.next + self.recv.window as u32 - 1;
        if min < self.recv.next || min > upper_bound {
            return Err(RustTcpError::UnexpectedSeqNum);
        }

        if max < self.recv.next || max > upper_bound {
            return Err(RustTcpError::UnexpectedSeqNum);
        }

        Ok(())
    }

    pub fn on_close(&mut self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        match self.state {
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                self.build_fin_packet(response)?;
            }
            _ => unimplemented!(),
        }

        Ok(())
    }

    fn build_fin_packet(&self, response: &mut Vec<u8>) -> Result<(), RustTcpError> {
        let writer = PacketBuilder::ipv4(self.connection.ip_dest, self.connection.ip_src, 64)
            .tcp(
                self.connection.port_src,
                self.connection.port_dest,
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
