pub mod connection {
    use crate::errors::errors::RustTcpError;
    use crate::packets::packets::TcpTlb;
    use etherparse::{IpNumber, Ipv4Header, TcpHeader};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    #[derive(PartialEq, Eq, Hash)]
    pub struct Connection {
        ip_src: [u8; 4],
        ip_dest: [u8; 4],
        port_src: u16,
        port_dest: u16,
    }

    pub fn on_request(
        request: &[u8],
        response: &mut Vec<u8>,
        connections: &mut HashMap<Connection, TcpTlb>,
        server_ipaddr: &Ipv4Addr,
    ) -> Result<(), RustTcpError> {
        let request_len = request.len();

        if request_len < (Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN) {
            return Err(RustTcpError::BadPacketSize(request_len));
        }

        let (iphdr, transport_hdr) = match Ipv4Header::from_slice(&request[..request_len]) {
            Ok((iphdr, tcphdr)) => (iphdr, tcphdr),
            Err(_) => return Err(RustTcpError::BadIpv4Header),
        };

        if let Err(e) = check_ipv4(&iphdr, &server_ipaddr) {
            return Err(e);
        }

        let (tcphdr, payload) = match TcpHeader::from_slice(transport_hdr) {
            Ok((tcphdr, payload)) => (tcphdr, payload),
            Err(_) => return Err(RustTcpError::BadTcpHeader),
        };

        let c = Connection {
            ip_src: iphdr.source,
            ip_dest: iphdr.destination,
            port_src: tcphdr.source_port,
            port_dest: tcphdr.destination_port,
        };

        connections
            .entry(c)
            .or_insert(TcpTlb::new(&iphdr))
            .on_request(&tcphdr, payload, response)?;

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
