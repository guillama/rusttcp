extern crate etherparse;

use crate::{connection::Connection, RustTcpError};
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
        PacketBuilder::ipv4(self.connection.ip_dest, self.connection.ip_src, 64)
            .tcp(
                self.connection.port_src,
                self.connection.port_dest,
                self.send.isa,
                self.send.window,
            )
            .ack(self.recv.next)
            .fin()
            .write(response, &[])
            .expect("Builder failed");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate etherparse;

    use crate::connection::*;
    use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
    use std::net::Ipv4Addr;

    #[test]
    fn send_syn_ack_with_correct_flags_and_seqnums_after_receiving_syn_request() {
        const CLIENT_SEQNUM: u32 = 100;

        let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
        let syn_request = build_syn_request(CLIENT_SEQNUM);
        let expected_resp_iphdr = build_ipv4_header();

        rust_tcp.open(22, "conn1");

        // Send SYN request
        let mut response: Vec<u8> = Vec::new();
        rust_tcp.on_request(&syn_request, &mut response).unwrap();

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

        let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
        let mut response_syn: Vec<u8> = Vec::new();
        let mut response_ack: Vec<u8> = Vec::new();
        let mut response_data: Vec<u8> = Vec::new();
        let data = [1, 2, 3];

        rust_tcp.open(22, "conn1");

        // Send SYN packet
        let syn_packet = build_syn_request(CLIENT_SEQNUM);
        rust_tcp.on_request(&syn_packet, &mut response_syn).unwrap();

        // Send ACK + DATA packet
        let ack_packet = build_ack_request(&[], CLIENT_SEQNUM + 1, &response_syn);
        let data_packet = build_ack_request(&data, CLIENT_SEQNUM + 1, &response_syn);

        rust_tcp.on_request(&ack_packet, &mut response_ack).unwrap();
        rust_tcp
            .on_request(&data_packet, &mut response_data)
            .unwrap();

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

        let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
        rust_tcp.open(22, "conn1");

        let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
        let data = &[1, 2, 3];
        let response_data = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, &resp_syn);

        let seqnum = CLIENT_SEQNUM + 1 + (data.len() as u32);
        let response_fin = send_fin_packet(&mut rust_tcp, seqnum, &response_data);

        // Check responses
        let (_, resp_tcphdr) = Ipv4Header::from_slice(&response_fin[..]).unwrap();
        let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

        assert_eq!(resp_tcphdr.acknowledgment_number, 104);
        assert_eq!(resp_tcphdr.ack, true);
    }

    fn do_handshake(rust_tcp: &mut RustTcp, seqnum: u32) -> Vec<u8> {
        let mut response_syn: Vec<u8> = Vec::new();
        let mut response_ack: Vec<u8> = Vec::new();

        let syn_packet = build_syn_request(seqnum);
        rust_tcp.on_request(&syn_packet, &mut response_syn).unwrap();

        let ack_packet = build_ack_request(&[], seqnum + 1, &response_syn);
        rust_tcp.on_request(&ack_packet, &mut response_ack).unwrap();

        // return response_sync because response_ack is empty after sending a ack without data
        response_syn
    }

    fn send_fin_packet(rust_tcp: &mut RustTcp, seqnum: u32, last_response: &[u8]) -> Vec<u8> {
        let mut response_fin: Vec<u8> = Vec::new();
        let fin_packet = build_fin_request(&[], seqnum, last_response);
        rust_tcp.on_request(&fin_packet, &mut response_fin).unwrap();

        response_fin
    }

    fn send_data_packet(
        rust_tcp: &mut RustTcp,
        seqnum: u32,
        data: &[u8],
        last_response: &[u8],
    ) -> Vec<u8> {
        let mut response_data: Vec<u8> = Vec::new();
        let data_packet = build_ack_request(data, seqnum, &last_response);
        rust_tcp
            .on_request(&data_packet, &mut response_data)
            .unwrap();

        response_data
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

    #[test]
    fn close_server_connection_after_receiving_fin_packet() {
        const CLIENT_SEQNUM: u32 = 100;

        let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
        let mut rust_tcp = RustTcp::new(&server_ip);
        rust_tcp.open(22, "conn2");

        let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
        let data = &[1, 2, 3];
        let response_data = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, &resp_syn);

        let seqnum = CLIENT_SEQNUM + 1 + (data.len() as u32);
        let _ = send_fin_packet(&mut rust_tcp, seqnum, &response_data);

        let mut fin_packet: Vec<u8> = Vec::new();

        rust_tcp.close("conn2");
        rust_tcp.on_user_event(&mut fin_packet).unwrap();

        // Check responses
        let (_, tcphdr_slice) = Ipv4Header::from_slice(&fin_packet).unwrap();
        let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();

        assert_eq!(tcphdr.fin, true);
        assert_eq!(tcphdr.ack, true);
        assert_eq!(tcphdr.acknowledgment_number, 104);
    }
}
