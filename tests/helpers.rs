use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
use rusttcp::connection::*;

pub fn receive_syn(rust_tcp: &mut RustTcp, seqnum: u32) -> Vec<u8> {
    let syn_packet = build_syn_packet(seqnum);
    let mut response: Vec<u8> = Vec::new();
    rust_tcp.on_packet(&syn_packet, &mut response).unwrap();

    response
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
        22,     //destination
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
    let _ = send_ack_to(server, seqnum + 1, &[], seqnum_from(&response_syn));

    // return response_sync because no response_ack is expected
    // after sending a ack without data
    response_syn
}

pub fn send_fin(rust_tcp: &mut RustTcp, seqnum: u32, last_response: &[u8]) -> Vec<u8> {
    let mut response_fin: Vec<u8> = Vec::new();
    let fin_packet = build_fin_packet(&[], seqnum, last_response);
    rust_tcp.on_packet(&fin_packet, &mut response_fin).unwrap();

    response_fin
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
    let mut response_data: Vec<u8> = Vec::new();
    let data_packet = build_ack_packet_to_server(data, seqnum, ack_seqnum);
    rust_tcp
        .on_packet(&data_packet, &mut response_data)
        .unwrap();

    response_data
}

pub fn send_ack_with_extract_to(
    rust_tcp: &mut RustTcp,
    seqnum: u32,
    data: &[u8],
    ack_seqnum: u32,
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let data_packet = build_ack_packet_to_server(data, seqnum, ack_seqnum);

    let mut response: Vec<u8> = Vec::new();
    rust_tcp.on_packet(&data_packet, &mut response).unwrap();

    let (iphdr, tcphdr, payload) = extract_packet(&response);
    (iphdr, tcphdr, payload.to_vec())
}

pub fn send_data_to(
    rust_tcp: &mut RustTcp,
    data: &[u8],
    seqnum: u32,
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let mut response: Vec<u8> = Vec::new();
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
    let mut data_request: Vec<u8> = Vec::new();
    let _ = client.on_user_event(&mut data_request).unwrap();
    data_request
}

pub fn on_packet_event(client: &mut RustTcp, packet: &[u8]) -> Vec<u8> {
    let mut ack_resp: Vec<u8> = Vec::new();
    client.on_packet(packet, &mut ack_resp).unwrap();
    ack_resp
}

pub fn on_packet_event_with_extract(
    client: &mut RustTcp,
    packet: &[u8],
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let mut ack_resp: Vec<u8> = Vec::new();
    client.on_packet(packet, &mut ack_resp).unwrap();

    let (iphdr, tcphdr, payload) = extract_packet(&ack_resp);
    (iphdr, tcphdr, payload.to_vec())
}

pub fn do_handshake(client: &mut RustTcp, server: &mut RustTcp) -> u32 {
    let mut syn_request: Vec<u8> = Vec::new();
    let mut syn_ack_resp: Vec<u8> = Vec::new();
    let mut client_ack: Vec<u8> = Vec::new();

    client
        .open(RustTcpMode::Active([192, 168, 1, 2], 22), "client")
        .unwrap();
    server.open(RustTcpMode::Passive(22), "server").unwrap();

    client.on_user_event(&mut syn_request).unwrap();
    server.on_packet(&syn_request, &mut syn_ack_resp).unwrap();
    client.on_packet(&syn_ack_resp, &mut client_ack).unwrap();
    server.on_packet(&client_ack, &mut vec![]).unwrap();

    seqnum_from(&syn_ack_resp) + 1
}

pub fn process_user_event_with_extract(
    client: &mut RustTcp,
) -> (Ipv4Header, TcpHeader, Vec<u8>, usize) {
    let mut data_request: Vec<u8> = Vec::new();
    let next_data_size = client.on_user_event(&mut data_request).unwrap();
    let (iphdr2, tcphdr2, payload2) = extract_packet(&data_request);

    (iphdr2, tcphdr2, payload2.to_vec(), next_data_size)
}
