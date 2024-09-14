extern crate etherparse;

use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
use rusttcp::connection::*;
use std::u32::MAX;

#[test]
fn send_syn_ack_with_correct_flags_and_seqnums_after_receiving_syn_packet() {
    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn1").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let response = receive_syn(&mut server, CLIENT_SEQNUM);

    // Check ACK response
    let expected_iphdr = build_ipv4_header([192, 168, 1, 2], [192, 168, 1, 1], TcpHeader::MIN_LEN);
    let (iphdr, tcphdr, _) = extract_packet(&response);

    assert_eq!(response.len(), Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN);
    assert_eq!(iphdr, expected_iphdr);
    assert_eq!(tcphdr.source_port, 22);
    assert_eq!(tcphdr.destination_port, 35000);
    assert_eq!(tcphdr.syn, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, CLIENT_SEQNUM + 1);
}

fn receive_syn(rust_tcp: &mut RustTcp, seqnum: u32) -> Vec<u8> {
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
        10,     // windows size)
    )
    .syn()
    .write(&mut packet, &[])
    .unwrap();

    packet
}

fn build_ipv4_header(ip_src: [u8; 4], ip_dst: [u8; 4], payload_len: usize) -> Ipv4Header {
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

fn extract_packet(packet: &[u8]) -> (Ipv4Header, TcpHeader, &[u8]) {
    let (iphdr, tcphdr_slice) = Ipv4Header::from_slice(&packet[..]).unwrap();
    let (tcphdr, payload) = TcpHeader::from_slice(tcphdr_slice).unwrap();

    (iphdr, tcphdr, payload)
}

#[test]
fn send_ack_with_correct_seqnum_after_a_3way_handshake_and_receiving_data() {
    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn1").unwrap();

    // Send SYN packet
    const CLIENT_SEQNUM: u32 = 100;
    let response_syn = receive_syn(&mut server, CLIENT_SEQNUM);

    // Send ACK + DATA packet
    let acknum = seqnum_from(&response_syn) + 1;
    let seqnum = CLIENT_SEQNUM + 1;
    let resp_ack = send_ack(&mut server, seqnum, &[], acknum);
    let (_, tcphdr, payload) = send_ack_with_extract(&mut server, seqnum, &[1, 2, 3], acknum);

    assert_eq!(resp_ack, &[]);
    assert_eq!(payload, []);
    assert_eq!(tcphdr.acknowledgment_number, 104);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.syn, false);
    assert_eq!(tcphdr.rst, false);
}

fn build_ack_packet(payload: &[u8], seqnum: u32, ack_seqnum: u32) -> Vec<u8> {
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
        10,     // windows size)
    )
    .ack(ack_seqnum)
    .write(&mut packet, payload)
    .unwrap();

    packet
}

fn seqnum_from(response: &[u8]) -> u32 {
    let (_, tcphdr, _) = extract_packet(&response);
    tcphdr.sequence_number
}

#[test]
fn send_fin_packet_close_server_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);
    rust_tcp.open(RustTcpMode::Passive(22), "conn1").unwrap();

    let resp_syn = do_server_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let response_data = send_ack(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let seqnum = CLIENT_SEQNUM + 1 + (data.len() as u32);
    let response_fin = send_fin(&mut rust_tcp, seqnum, &response_data);

    // Check responses
    let (_, tcphdr, _) = extract_packet(&response_fin);

    assert_eq!(tcphdr.acknowledgment_number, 104);
    assert_eq!(tcphdr.ack, true);
}

fn do_server_handshake(rust_tcp: &mut RustTcp, seqnum: u32) -> Vec<u8> {
    let response_syn = receive_syn(rust_tcp, seqnum);
    let _ = send_ack(rust_tcp, seqnum + 1, &[], seqnum_from(&response_syn));

    // return response_sync because no response_ack is expected
    // after sending a ack without data
    response_syn
}

fn send_fin(rust_tcp: &mut RustTcp, seqnum: u32, last_response: &[u8]) -> Vec<u8> {
    let mut response_fin: Vec<u8> = Vec::new();
    let fin_packet = build_fin_packet(&[], seqnum, last_response);
    rust_tcp.on_packet(&fin_packet, &mut response_fin).unwrap();

    response_fin
}

fn send_ack(rust_tcp: &mut RustTcp, seqnum: u32, data: &[u8], ack_seqnum: u32) -> Vec<u8> {
    let mut response_data: Vec<u8> = Vec::new();
    let data_packet = build_ack_packet(data, seqnum, ack_seqnum);
    rust_tcp
        .on_packet(&data_packet, &mut response_data)
        .unwrap();

    response_data
}

fn send_ack_with_extract(
    rust_tcp: &mut RustTcp,
    seqnum: u32,
    data: &[u8],
    ack_seqnum: u32,
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let data_packet = build_ack_packet(data, seqnum, ack_seqnum);

    let mut response: Vec<u8> = Vec::new();
    rust_tcp.on_packet(&data_packet, &mut response).unwrap();

    let (iphdr, tcphdr, payload) = extract_packet(&response);
    (iphdr, tcphdr, payload.to_vec())
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
        10,     // windows size)
    )
    .ack(tcphdr.sequence_number + 1)
    .fin()
    .write(&mut packet, payload)
    .unwrap();

    packet
}

#[test]
fn close_server_connection_after_receiving_fin_packet() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);

    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let response_data = send_ack(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let seqnum = CLIENT_SEQNUM + 1 + (data.len() as u32);
    let _ = send_fin(&mut server, seqnum, &response_data);

    server.close("conn2");

    let (_, tcphdr, _, _) = process_user_event_with_extract(&mut server);

    assert_eq!(tcphdr.fin, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 104);
}

#[test]
fn send_second_packet_with_same_sequence_number_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr1, _) = send_ack_with_extract(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);
    let (_, tcphdr2, _) = send_ack_with_extract(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let read_size: usize = server.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr1.rst, false);
    assert_eq!(tcphdr1.ack, true);
    assert_eq!(tcphdr1.acknowledgment_number, 104);

    assert_eq!(tcphdr2.rst, false);
    assert_eq!(tcphdr2.ack, true);
    assert_eq!(tcphdr2.acknowledgment_number, 104);

    assert_eq!(read_size, 3);
    assert_eq!(&recv_buf[..3], &[1, 2, 3]);
}

#[test]
fn send_packet_with_sequence_number_higher_than_the_receive_window_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr, _) =
        send_ack_with_extract(&mut rust_tcp, CLIENT_SEQNUM + 300, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_packet_bigger_than_the_receive_window_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr, _) = send_ack_with_extract(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_data_with_max_u32_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 1;

    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr, _) = send_ack_with_extract(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 4);
    assert_eq!(nbytes_read, 5);
}

#[test]
fn send_data_with_wrapped_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 5;

    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data1 = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let ack_seqnum = seqnum_from(&resp_syn);
    let response_data = send_ack(&mut server, CLIENT_SEQNUM + 1, data1, ack_seqnum);

    let seqnum = CLIENT_SEQNUM.wrapping_add(data1.len() as u32 + 1);
    let data2 = &[0x1, 0x2, 0x3];
    let ack_seqnum = seqnum_from(&response_data);
    let (_, tcphdr, _) = send_ack_with_extract(&mut server, seqnum, data2, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 3);
    assert_eq!(nbytes_read, 8);
}

#[test]
fn send_reset_when_receiving_ack_packet_on_closed_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcp::new([192, 168, 1, 2]);

    // No call to open()

    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let (_, tcphdr, _) = send_ack_with_extract(&mut server, CLIENT_SEQNUM + 1, data, 300);

    let expected_seqnum = CLIENT_SEQNUM + 1 + data.len() as u32;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 300);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_packet_on_closed_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);

    // No call to open()

    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let response_data = send_data(&mut rust_tcp, CLIENT_SEQNUM + 1, data);

    // Check response
    let (_, tcphdr, _) = extract_packet(&response_data);
    let expected_seqnum = CLIENT_SEQNUM + 1 + data.len() as u32;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 0);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

fn send_data(rust_tcp: &mut RustTcp, seqnum: u32, data: &[u8]) -> Vec<u8> {
    let mut response_data: Vec<u8> = Vec::new();
    let data_packet = build_packet(data, seqnum);
    rust_tcp
        .on_packet(&data_packet, &mut response_data)
        .unwrap();

    response_data
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
        10,     // windows size)
    )
    .write(&mut packet, payload)
    .unwrap();

    packet
}

#[test]
fn send_reset_when_receiving_bad_ack_seqnum_during_handshake() {
    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 101;
    let response_syn = receive_syn(&mut rust_tcp, CLIENT_SEQNUM);
    let ack_seqnum = seqnum_from(&response_syn).wrapping_add(20000);
    let (_, tcphdr, _) = send_ack_with_extract(&mut rust_tcp, CLIENT_SEQNUM, &[], ack_seqnum);

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, ack_seqnum);
    assert_eq!(tcphdr.acknowledgment_number, CLIENT_SEQNUM);
}

#[test]
fn send_reset_when_receiving_bad_ack_during_handshake() {
    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let _ = receive_syn(&mut rust_tcp, CLIENT_SEQNUM + 1);
    let reset_resp = receive_syn(&mut rust_tcp, CLIENT_SEQNUM + 1);

    let (_, tcphdr, _) = extract_packet(&reset_resp);
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 0);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_bad_syn_during_handshake() {
    let mut rust_tcp = RustTcp::new([192, 168, 1, 2]);
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let (_, tcphdr, _) = send_ack_with_extract(&mut rust_tcp, CLIENT_SEQNUM + 1, &[], 42);
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 42);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_syn_packet_on_opening_active_connection() {
    use RustTcpMode::Active;

    let mut client = RustTcp::new([192, 168, 1, 1]);
    client.open(Active([192, 168, 1, 2], 22), "client").unwrap();

    let (iphdr, tcphdr, payload, _) = process_user_event_with_extract(&mut client);
    let expected_iphdr = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], TcpHeader::MIN_LEN);

    assert_eq!(iphdr, expected_iphdr);
    assert_eq!(tcphdr.source_port, 36000);
    assert_eq!(tcphdr.destination_port, 22);
    assert_eq!(tcphdr.syn, true);
    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, false);
    assert_eq!(payload, &[]);
}

#[test]
fn send_ack_packet_after_receiving_syn_ack_packet() {
    use RustTcpMode::{Active, Passive};

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]);
    client.open(Active([192, 168, 1, 2], 22), "client").unwrap();
    server.open(Passive(22), "server").unwrap();

    let syn_request = process_user_event(&mut client);
    let syn_ack_resp = request_packet_event(&mut server, &syn_request);

    let (_, tcphdr, payload) = request_packet_event_with_extract(&mut client, &syn_ack_resp);
    let expected_ack = seqnum_from(&syn_ack_resp) + 1;

    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, expected_ack);
    assert_eq!(tcphdr.syn, false);
    assert_eq!(tcphdr.rst, false);
    assert_eq!(payload, &[]);
}

fn process_user_event(client: &mut RustTcp) -> Vec<u8> {
    let mut data_request: Vec<u8> = Vec::new();
    let _ = client.on_user_event(&mut data_request).unwrap();
    data_request
}

fn request_packet_event(client: &mut RustTcp, packet: &[u8]) -> Vec<u8> {
    let mut ack_resp: Vec<u8> = Vec::new();
    client.on_packet(packet, &mut ack_resp).unwrap();
    ack_resp
}

fn request_packet_event_with_extract(
    client: &mut RustTcp,
    packet: &[u8],
) -> (Ipv4Header, TcpHeader, Vec<u8>) {
    let mut ack_resp: Vec<u8> = Vec::new();
    client.on_packet(packet, &mut ack_resp).unwrap();

    let (iphdr, tcphdr, payload) = extract_packet(&ack_resp);
    (iphdr, tcphdr, payload.to_vec())
}

#[test]
fn send_data_with_length_lower_than_windows_size_on_user_request() {
    use RustTcpMode::{Active, Passive};

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]);
    client.open(Active([192, 168, 1, 2], 22), "client").unwrap();
    server.open(Passive(22), "server").unwrap();

    // 3-way handshake
    let expected_acknum = do_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6];
    client.write("client", data).unwrap();

    let (iphdr, tcphdr, payload, _) = process_user_event_with_extract(&mut client);
    let payload_len = TcpHeader::MIN_LEN + data.len();
    let expected_iphdr = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len);

    assert_eq!(iphdr, expected_iphdr);
    assert_eq!(payload, &[1, 2, 3, 4, 5, 6]);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, expected_acknum);
    assert_eq!(tcphdr.syn, false);
    assert_eq!(tcphdr.rst, false);
}

#[test]
fn send_data_with_length_bigger_than_windows_size_on_user_request() {
    use RustTcpMode::{Active, Passive};

    const WINDOW_SIZE: u16 = 5;

    let mut client = RustTcp::new([192, 168, 1, 1]).window_size(WINDOW_SIZE);
    let mut server = RustTcp::new([192, 168, 1, 2]);
    client.open(Active([192, 168, 1, 2], 22), "client").unwrap();
    server.open(Passive(22), "server").unwrap();

    // 3-way handshake
    let expected_acknum = do_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8];
    client.write("client", data).unwrap();

    let (iphdr1, tcphdr1, payload1, next_data_size) = process_user_event_with_extract(&mut client);
    let payload_len1 = TcpHeader::MIN_LEN + WINDOW_SIZE as usize;
    let expected_iphdr1 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len1);

    let (iphdr2, tcphdr2, payload2, next_data_size2) = process_user_event_with_extract(&mut client);
    let payload_len2 = TcpHeader::MIN_LEN + (data.len() - WINDOW_SIZE as usize);
    let expected_iphdr2 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len2);

    assert_eq!(next_data_size, 3);
    assert_eq!(next_data_size2, 0);

    assert_eq!(iphdr1, expected_iphdr1);
    assert_eq!(payload1, &[1, 2, 3, 4, 5]);
    assert_eq!(tcphdr1.ack, true);
    assert_eq!(tcphdr1.acknowledgment_number, expected_acknum);

    assert_eq!(iphdr2, expected_iphdr2);
    assert_eq!(payload2, &[6, 7, 8]);
    assert_eq!(tcphdr2.ack, true);
    assert_eq!(tcphdr2.acknowledgment_number, expected_acknum);
}

fn do_handshake(client: &mut RustTcp, server: &mut RustTcp) -> u32 {
    let mut syn_request: Vec<u8> = Vec::new();
    let mut syn_ack_resp: Vec<u8> = Vec::new();

    client.on_user_event(&mut syn_request).unwrap();
    server.on_packet(&syn_request, &mut syn_ack_resp).unwrap();
    client.on_packet(&syn_ack_resp, &mut vec![]).unwrap();

    seqnum_from(&syn_ack_resp) + 1
}

fn process_user_event_with_extract(
    client: &mut RustTcp,
) -> (Ipv4Header, TcpHeader, Vec<u8>, usize) {
    let mut data_request: Vec<u8> = Vec::new();
    let next_data_size = client.on_user_event(&mut data_request).unwrap();
    let (iphdr2, tcphdr2, payload2) = extract_packet(&data_request);

    (iphdr2, tcphdr2, payload2.to_vec(), next_data_size)
}
