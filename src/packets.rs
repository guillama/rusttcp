extern crate etherparse;

use crate::{connection::Connection, RustTcpError};
use etherparse::{PacketBuilder, TcpHeader};

enum TcpState {
    Listen,
    SynReceived,
    Established,
    LastAck,
}

#[allow(dead_code)]
struct TcpRecvContext {
    isa: u32,
    next: u32,
    window: u16,
}

#[allow(dead_code)]
struct TcpSendContext {
    isa: u32,
    next: u32,
    window: u16,
}

pub struct TcpTlb {
    state: TcpState,
    connection: Connection,
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
                self.recv.next = tcphdr.sequence_number;
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
        self.recv.next += payload.len() as u32;

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

        self.recv_buf.extend(payload.iter());

        Ok(())
    }

        if tcphdr.fin {
            self.state = TcpState::LastAck;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate etherparse;

    use super::*;
    use crate::connection::{on_request, Connection};
    use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
    use std::{collections::HashMap, net::Ipv4Addr};

    #[test]
    fn send_syn_ack_with_correct_flags_and_seqnums_after_receiving_syn_request() {
        const CLIENT_SEQNUM: u32 = 100;

        let ip = Ipv4Addr::from([192, 168, 1, 2]);
        let syn_request = build_syn_request(CLIENT_SEQNUM);
        let expected_resp_iphdr = build_ipv4_header();

        // Send SYN request
        let mut response: Vec<u8> = Vec::new();
        let mut connections: HashMap<Connection, TcpTlb> = HashMap::new();
        on_request(&syn_request, &mut response, &mut connections, &ip).unwrap();

        // Check ACK response
        let (resp_iphdr, resp_tcphdr) = Ipv4Header::from_slice(&response[..]).unwrap();
        let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

        assert_eq!(response.len(), Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN);
        assert_eq!(resp_iphdr, expected_resp_iphdr);
        assert_eq!(resp_tcphdr.syn, true);
        assert_eq!(resp_tcphdr.ack, true);
        assert_eq!(resp_tcphdr.destination_port, 22);
        assert_eq!(resp_tcphdr.acknowledgment_number, CLIENT_SEQNUM + 1);
    }

    fn build_syn_request(seqnum: u32) -> Vec<u8> {
        let mut request: Vec<u8> = Vec::new();

        PacketBuilder::ipv4(
            [192, 168, 1, 1], // source
            [192, 168, 1, 2], // destination
            64,               // ttl
        )
        .tcp(
            35000,  // source
            22,     //destination
            seqnum, //seq
            10,     // windows size)
        )
        .syn()
        .write(&mut request, &[])
        .unwrap();

        request
    }

    fn build_ipv4_header() -> Ipv4Header {
        let mut iphdr = Ipv4Header::new(
            TcpHeader::MIN_LEN as u16,
            64, // ttl
            IpNumber::TCP,
            [192, 168, 1, 2], //source
            [192, 168, 1, 1], //destination
        )
        .unwrap();

        iphdr.header_checksum = iphdr.calc_header_checksum();
        iphdr
    }

    #[test]
    fn send_ack_with_correct_seqnum_after_a_3way_handshake_and_receiving_data() {
        const CLIENT_SEQNUM: u32 = 100;

        let ip = Ipv4Addr::from([192, 168, 1, 2]);
        let mut connections: HashMap<Connection, TcpTlb> = HashMap::new();
        let mut response_syn: Vec<u8> = Vec::new();
        let mut response_ack: Vec<u8> = Vec::new();
        let mut response_data: Vec<u8> = Vec::new();
        let data = [1, 2, 3];

        // Send SYN packet
        let syn_packet = build_syn_request(CLIENT_SEQNUM);
        on_request(&syn_packet, &mut response_syn, &mut connections, &ip).unwrap();

        // Send ACK + DATA packet
        let ack_packet = build_ack_request(&[], CLIENT_SEQNUM + 1, &response_syn);
        let data_packet = build_ack_request(&data, CLIENT_SEQNUM + 1, &response_syn);

        on_request(&ack_packet, &mut response_ack, &mut connections, &ip).unwrap();
        on_request(&data_packet, &mut response_data, &mut connections, &ip).unwrap();

        // Check responses
        let (_, resp_tcphdr) = Ipv4Header::from_slice(&response_data[..]).unwrap();
        let (resp_tcphdr, resp_payload) = TcpHeader::from_slice(resp_tcphdr).unwrap();

        assert_eq!(response_ack, Vec::new());
        assert_eq!(resp_payload, []);
        assert_eq!(resp_tcphdr.acknowledgment_number, 104);
        assert_eq!(resp_tcphdr.ack, true);
        assert_eq!(resp_tcphdr.syn, false);
    }

    fn build_ack_request(payload: &[u8], seq: u32, response_syn: &[u8]) -> Vec<u8> {
        let mut request: Vec<u8> = Vec::new();

        let (_, resp_tcphdr) = Ipv4Header::from_slice(&response_syn[..]).unwrap();
        let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

        PacketBuilder::ipv4(
            [192, 168, 1, 1], // source
            [192, 168, 1, 2], // destination
            64,               // ttl
        )
        .tcp(
            35000, // source
            22,    //destination
            seq,   //seq
            10,    // windows size)
        )
        .ack(resp_tcphdr.sequence_number + 1)
        .write(&mut request, payload)
        .unwrap();

        request
    }

    #[test]
    fn send_fin_packet_close_server_connection() {
        const CLIENT_SEQNUM: u32 = 100;

        let ip = Ipv4Addr::from([192, 168, 1, 2]);
        let mut connections: HashMap<Connection, TcpTlb> = HashMap::new();
        let mut response_data: Vec<u8> = Vec::new();
        let mut response_fin: Vec<u8> = Vec::new();

        let response_syn = do_handshake(&mut connections, &ip, CLIENT_SEQNUM);

        let data = [1, 2, 3];
        let data_packet = build_ack_request(&data, CLIENT_SEQNUM + 1, &response_syn);
        on_request(&data_packet, &mut response_data, &mut connections, &ip).unwrap();

        let seqnum = CLIENT_SEQNUM + 1 + (data.len() as u32);
        let fin_packet = build_fin_request(&[], seqnum, &response_data);
        on_request(&fin_packet, &mut response_fin, &mut connections, &ip).unwrap();

        // Check responses
        let (_, resp_tcphdr) = Ipv4Header::from_slice(&response_fin[..]).unwrap();
        let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

        assert_eq!(resp_tcphdr.acknowledgment_number, 104);
        assert_eq!(resp_tcphdr.ack, true);
    }

    fn do_handshake(
        connections: &mut HashMap<Connection, TcpTlb>,
        ip: &Ipv4Addr,
        seqnum: u32,
    ) -> Vec<u8> {
        let mut response_syn: Vec<u8> = Vec::new();
        let mut response_ack: Vec<u8> = Vec::new();

        let syn_packet = build_syn_request(seqnum);
        on_request(&syn_packet, &mut response_syn, connections, ip).unwrap();

        let ack_packet = build_ack_request(&[], seqnum + 1, &response_syn);
        on_request(&ack_packet, &mut response_ack, connections, ip).unwrap();

        // return response_sync because response_ack is empty after sending a ack without data
        response_syn
    }

    fn build_fin_request(payload: &[u8], seq: u32, response_syn: &[u8]) -> Vec<u8> {
        let mut request: Vec<u8> = Vec::new();

        let (_, resp_tcphdr) = Ipv4Header::from_slice(&response_syn[..]).unwrap();
        let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

        PacketBuilder::ipv4(
            [192, 168, 1, 1], // source
            [192, 168, 1, 2], // destination
            64,               // ttl
        )
        .tcp(
            35000, // source
            22,    //destination
            seq,   //seq
            10,    // windows size)
        )
        .ack(resp_tcphdr.sequence_number + 1)
        .fin()
        .write(&mut request, payload)
        .unwrap();

        request
    }
}
