use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
use rusttcp::connection::*;

pub fn receive_syn(rust_tcp: &mut RustTcp, seqnum: u32) -> Vec<u8> {
    let syn_packet = build_syn_packet(seqnum);
    let mut response = [0; 1400];
    let n = rust_tcp.on_packet(&syn_packet, &mut response).unwrap();

    response[..n].to_vec()
}

fn build_syn_packet(seqnum: u32) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    PacketBuilder::ipv4(
        [192, 168, 1, 1], // source
        [192, 168, 1, 2], // destination
        64,               // ttl
    )
    .tcp(
        35000,  // source
        22,     //destination
        seqnum, //seq
        10,     // window size)
    )
    .syn()
    .write(&mut packet, &[])
    .unwrap();

    packet
}

pub fn build_ipv4_header(ip_src: [u8; 4], ip_dst: [u8; 4], payload_len: usize) -> Ipv4Header {
    let mut iphdr = Ipv4Header::new(
        TcpHeader::MIN_LEN as u16,
        64, // ttl
        IpNumber::TCP,
        ip_src,
        ip_dst,
    )
    .unwrap();

    iphdr.set_payload_len(payload_len).unwrap();
    iphdr.header_checksum = iphdr.calc_header_checksum();
    iphdr
}

pub fn extract_packet(packet: &[u8]) -> (Ipv4Header, TcpHeader, &[u8]) {
    let (iphdr, tcphdr_slice) = Ipv4Header::from_slice(&packet[..]).unwrap();
    let (tcphdr, payload) = TcpHeader::from_slice(tcphdr_slice).unwrap();

    (iphdr, tcphdr, payload)
}

pub fn build_ack_packet_to_server(payload: &[u8], seqnum: u32, ack_seqnum: u32) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    PacketBuilder::ipv4(
        [192, 168, 1, 1], // source
        [192, 168, 1, 2], // destination
        64,               // ttl
    )
    .tcp(
        35000,  // source
        22,     // destination
        seqnum, // seq
        10,     // window size)
    )
    .ack(ack_seqnum)
    .write(&mut packet, payload)
    .unwrap();

    packet
}

pub fn build_ack_packet_to_client(payload: &[u8], seqnum: u32, ack_seqnum: u32) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    PacketBuilder::ipv4(
        [192, 168, 1, 2], // source
        [192, 168, 1, 1], // destination
        64,               // ttl
    )
    .tcp(
        22,     // source
        36000,  //destination
        seqnum, //seq
        10,     // window size)
    )
    .ack(ack_seqnum)
    .write(&mut packet, payload)
    .unwrap();

    packet
}

pub fn seqnum_from(response: &[u8]) -> u32 {
    let (_, tcphdr, _) = extract_packet(&response);
    tcphdr.sequence_number
}

pub fn do_server_handshake(server: &mut RustTcp, seqnum: u32) -> Vec<u8> {
    let response_syn = receive_syn(server, seqnum);
    let _ = send_ack_to(server, seqnum + 1, &[], seqnum_from(&response_syn) + 1);

    // return response_syn because no response_ack is expected
    // after sending a ack without data
    response_syn
}

pub fn send_fin_to(rust_tcp: &mut RustTcp, seqnum: u32, last_response: &[u8]) -> Vec<u8> {
    let mut response_fin = [0; 1400];
    let fin_packet = build_fin_packet(&[], seqnum, last_response);
    let n = rust_tcp.on_packet(&fin_packet, &mut response_fin).unwrap();

    response_fin[..n].to_vec()
}

fn build_fin_packet(payload: &[u8], seqnum: u32, response_syn: &[u8]) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    let (_, tcphdr, _) = extract_packet(&response_syn);

    PacketBuilder::ipv4(
        [192, 168, 1, 1], // source
        [192, 168, 1, 2], // destination
        64,               // ttl
    )
    .tcp(
        35000,  // source
        22,     //destination
        seqnum, //seq
        10,     // window size)
    )
    .ack(tcphdr.sequence_number + 1)
    .fin()
    .write(&mut packet, payload)
    .unwrap();

    packet
}

pub fn send_ack_to(rust_tcp: &mut RustTcp, seqnum: u32, data: &[u8], ack_seqnum: u32) -> Vec<u8> {
    let mut response_data = [0; 1400];
    let data_packet = build_ack_packet_to_server(data, seqnum, ack_seqnum);
    let n = rust_tcp
        .on_packet(&data_packet, &mut response_data)
        .unwrap();

    response_data[..n].to_vec()
}

pub fn send_ack_with_extract_to(
    rust_tcp: &mut RustTcp,
    seqnum: u32,
    data: &[u8],
    ack_seqnum: u32,
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let data_packet = build_ack_packet_to_server(data, seqnum, ack_seqnum);

    let mut response = [0; 1400];
    let n = rust_tcp.on_packet(&data_packet, &mut response).unwrap();

    let (iphdr, tcphdr, payload) = extract_packet(&response[..n]);
    (iphdr, tcphdr, payload.to_vec())
}

pub fn send_data_to(
    rust_tcp: &mut RustTcp,
    data: &[u8],
    seqnum: u32,
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let mut response = [0; 1400];
    let data_packet = build_packet(data, seqnum);
    rust_tcp.on_packet(&data_packet, &mut response).unwrap();

    let (iphdr, tcphdr, payload) = extract_packet(&response);
    (iphdr, tcphdr, payload.to_vec())
}

fn build_packet(payload: &[u8], seqnum: u32) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    PacketBuilder::ipv4(
        [192, 168, 1, 1], // source
        [192, 168, 1, 2], // destination
        64,               // ttl
    )
    .tcp(
        35000,  // source
        22,     // destination
        seqnum, // seq
        10,     // window size)
    )
    .write(&mut packet, payload)
    .unwrap();

    packet
}

pub fn process_user_event(client: &mut RustTcp) -> Vec<u8> {
    let mut data_request = [0; 1400];
    let n = client.on_user_event(&mut data_request).unwrap();
    data_request[..n].to_vec()
}

pub fn on_packet_event(client: &mut RustTcp, packet: &[u8]) -> Vec<u8> {
    let mut ack_resp = [0; 1400];
    let n = client.on_packet(packet, &mut ack_resp).unwrap();
    ack_resp[..n].to_vec()
}

pub fn on_packet_event_with_extract(
    client: &mut RustTcp,
    packet: &[u8],
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let mut ack_resp = [0; 1400];
    let n = client.on_packet(packet, &mut ack_resp).unwrap();

    let (iphdr, tcphdr, payload) = extract_packet(&ack_resp[..n]);
    (iphdr, tcphdr, payload.to_vec())
}

pub fn open_and_handshake(client: &mut RustTcp, server: &mut RustTcp) -> (i32, i32, u32) {
    let mut syn_request = [0; 1400];
    let mut syn_ack_resp = [0; 1400];
    let mut client_ack = [0; 1400];

    let fd_client = client
        .open(RustTcpMode::Active([192, 168, 1, 2], 22))
        .unwrap();
    let fd_server = server.open(RustTcpMode::Passive(22)).unwrap();

    client.on_user_event(&mut syn_request).unwrap();
    server.on_packet(&syn_request, &mut syn_ack_resp).unwrap();
    client.on_packet(&syn_ack_resp, &mut client_ack).unwrap();
    server.on_packet(&client_ack, &mut vec![]).unwrap();

    let acked_seqnum = seqnum_from(&syn_ack_resp) + 1;

    (fd_client, fd_server, acked_seqnum)
}

pub fn process_user_event_with_extract(
    client: &mut RustTcp,
) -> (Ipv4Header, TcpHeader, Vec<u8>, usize) {
    let mut data_request = [0; 1400];
    let n = client.on_user_event(&mut data_request).unwrap();
    dbg!(&n);
    let (iphdr2, tcphdr2, payload2) = extract_packet(&data_request[..n]);

    (iphdr2, tcphdr2, payload2.to_vec(), n)
}

pub fn process_timeout_event(client: &mut RustTcp) -> Vec<u8> {
    let mut data_request = [0; 1400];
    if let Ok(n) = client.on_timer_event(&mut data_request) {
        return data_request[..n].to_vec();
    }

    Vec::new()
}

pub fn build_reset_packet() -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    PacketBuilder::ipv4(
        [192, 168, 1, 1], // source
        [192, 168, 1, 2], // destination
        64,               // ttl
    )
    .tcp(
        35000, // source
        22,    //destination
        0,     //seq
        10,    // window size)
    )
    .rst()
    .write(&mut packet, &[])
    .unwrap();

    packet
}
