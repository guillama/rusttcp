extern crate etherparse;

pub mod packets {
    use crate::RustTcpError;
    use etherparse::{IpNumber, Ipv4Header};
    use etherparse::{PacketBuilder, TcpHeader};
    use std::io::Write;
    use std::net::Ipv4Addr;

    const TUN_HEADER_SIZE: usize = 4;

    pub fn on_request(
        request: &mut Vec<u8>,
        response: &mut Vec<u8>,
        server_ipaddr: &Ipv4Addr,
    ) -> Result<(), RustTcpError> {
        let tun_header = &request[..TUN_HEADER_SIZE];
        let request_len = request.len();

        // Skip the first 4 bytes (irrelevant data = TUN header)
        if request_len < (TUN_HEADER_SIZE + Ipv4Header::MIN_LEN) {
            return Err(RustTcpError::BadPacketSize(request_len));
        }

        let (req_iphr, req_tcphdr) =
            match Ipv4Header::from_slice(&request[tun_header.len()..request_len]) {
                Ok((iphdr, tcphdr)) => (iphdr, tcphdr),
                Err(_) => return Err(RustTcpError::BadIpv4Header),
            };

        if let Err(e) = check_ipv4(&req_iphr, &server_ipaddr) {
            return Err(e);
        }

        let (req_tcphr, payload) = match TcpHeader::from_slice(req_tcphdr) {
            Ok((tcphdr, payload)) => (tcphdr, payload),
            Err(_) => return Err(RustTcpError::BadTcpHeader),
        };

        println!("{:?}", req_tcphr);

        let response_builder =
            PacketBuilder::ipv4(req_iphr.destination, req_iphr.source, req_iphr.time_to_live)
                .tcp(
                    req_tcphr.source_port,
                    req_tcphr.destination_port,
                    3000,
                    req_tcphr.window_size,
                )
                .syn()
                .ack(req_tcphr.sequence_number + 1);

        response.write(tun_header).expect("Builder failed");
        response_builder
            .write(response, payload)
            .expect("Builder failed");

        Ok(())
    }

    fn check_ipv4(hdr: &Ipv4Header, server_ip: &Ipv4Addr) -> Result<(), RustTcpError> {
        if hdr.destination != server_ip.octets() {
            return Err(RustTcpError::BadAddress(hdr.destination));
        }

        if hdr.protocol != IpNumber::TCP {
            return Err(RustTcpError::BadProto(hdr.protocol.into()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate etherparse;
    use crate::packets::packets::on_request;
    use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
    use std::io::Write;
    use std::net::Ipv4Addr;

    #[test]
    fn send_syn_ack_response_after_receiving_syn_request() {
        let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
        let tun_header = [0, 0, 0x80, 0];
        let ttl = 2;

        // Build request
        let mut request: Vec<u8> = Vec::new();
        request.write(&tun_header[..]).unwrap();
        PacketBuilder::ipv4([192, 168, 1, 1], [192, 168, 1, 2], ttl)
            .tcp(35000, 22, 1000, 10)
            .syn()
            .write(&mut request, &[])
            .unwrap();

        // Build expected response
        let mut expected_iphdr = Ipv4Header::new(
            TcpHeader::MIN_LEN as u16,
            ttl,
            IpNumber::TCP,
            [192, 168, 1, 2], //source
            [192, 168, 1, 1], //destination
        )
        .unwrap();
        let crc = expected_iphdr.calc_header_checksum();
        expected_iphdr.header_checksum = crc;

        // Send request
        let mut response: Vec<u8> = Vec::new();
        on_request(&mut request, &mut response, &server_ip).unwrap();

        // Check response
        let resp_tun_hdr = &response[..tun_header.len()];
        let (resp_iphdr, resp_tcphdr) =
            Ipv4Header::from_slice(&response[tun_header.len()..]).unwrap();
        let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();
        let expect_len = tun_header.len() + Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN;

        assert_eq!(response.len(), expect_len);
        assert_eq!(resp_tun_hdr, tun_header);
        assert_eq!(resp_iphdr, expected_iphdr);

        assert_eq!(resp_tcphdr.syn, true);
        assert_eq!(resp_tcphdr.destination_port, 22);
        assert_eq!(resp_tcphdr.ack, true);
        assert_eq!(resp_tcphdr.acknowledgment_number, 1001);
    }
}
