extern crate etherparse;

use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
use rusttcp::connection::*;
use std::{net::Ipv4Addr, u32::MAX};

#[test]
fn send_syn_ack_with_correct_flags_and_seqnums_after_receiving_syn_packet() {
    let expected_resp_iphdr = build_ipv4_header([192, 168, 1, 2], [192, 168, 1, 1]);
    let mut server = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
    server.open(RustTcpMode::Passive(22), "conn1").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let response = receive_syn_packet(&mut server, CLIENT_SEQNUM);

    // Check ACK response
    let (resp_iphdr, resp_tcphdr) = Ipv4Header::from_slice(&response[..]).unwrap();
    let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

    assert_eq!(response.len(), Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN);
    assert_eq!(resp_iphdr, expected_resp_iphdr);
    assert_eq!(resp_tcphdr.source_port, 22);
    assert_eq!(resp_tcphdr.destination_port, 35000);
    assert_eq!(resp_tcphdr.syn, true);
    assert_eq!(resp_tcphdr.ack, true);
    assert_eq!(resp_tcphdr.acknowledgment_number, CLIENT_SEQNUM + 1);
}

fn receive_syn_packet(rust_tcp: &mut RustTcp, seqnum: u32) -> Vec<u8> {
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

fn build_ipv4_header(ip_src: [u8; 4], ip_dst: [u8; 4]) -> Ipv4Header {
    let mut iphdr = Ipv4Header::new(
        TcpHeader::MIN_LEN as u16,
        64, // ttl
        IpNumber::TCP,
        ip_src,
        ip_dst,
    )
    .unwrap();

    iphdr.header_checksum = iphdr.calc_header_checksum();
    iphdr
}

#[test]
fn send_ack_with_correct_seqnum_after_a_3way_handshake_and_receiving_data() {
    let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
    rust_tcp.open(RustTcpMode::Passive(22), "conn1").unwrap();

    // Send SYN packet
    const CLIENT_SEQNUM: u32 = 100;
    let response_syn = receive_syn_packet(&mut rust_tcp, CLIENT_SEQNUM);

    // Send ACK + DATA packet
    let ack_seqnum = get_ack_seqnum(&response_syn) + 1;
    let resp_ack = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, &[], ack_seqnum);
    let resp_data = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, &[1, 2, 3], ack_seqnum);

    // Check responses
    let (_, resp_tcphdr) = Ipv4Header::from_slice(&resp_data[..]).unwrap();
    let (resp_tcphdr, resp_payload) = TcpHeader::from_slice(resp_tcphdr).unwrap();

    assert_eq!(resp_ack, Vec::new());
    assert_eq!(resp_payload, []);
    assert_eq!(resp_tcphdr.acknowledgment_number, 104);
    assert_eq!(resp_tcphdr.ack, true);
    assert_eq!(resp_tcphdr.syn, false);
    assert_eq!(resp_tcphdr.rst, false);
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

fn get_ack_seqnum(response: &[u8]) -> u32 {
    let (_, resp_tcphdr) = Ipv4Header::from_slice(response).unwrap();
    let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

    resp_tcphdr.sequence_number
}

#[test]
fn send_fin_packet_close_server_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));

    rust_tcp.open(RustTcpMode::Passive(22), "conn1").unwrap();

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = get_ack_seqnum(&resp_syn);
    let response_data = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let seqnum = CLIENT_SEQNUM + 1 + (data.len() as u32);
    let response_fin = send_fin_packet(&mut rust_tcp, seqnum, &response_data);

    // Check responses
    let (_, resp_tcphdr) = Ipv4Header::from_slice(&response_fin[..]).unwrap();
    let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

    assert_eq!(resp_tcphdr.acknowledgment_number, 104);
    assert_eq!(resp_tcphdr.ack, true);
}

fn do_handshake(rust_tcp: &mut RustTcp, seqnum: u32) -> Vec<u8> {
    let response_syn = receive_syn_packet(rust_tcp, seqnum);
    let _ = send_ack_packet(rust_tcp, seqnum + 1, &[], get_ack_seqnum(&response_syn));

    // return response_sync because no response_ack is expected
    // after sending a ack without data
    response_syn
}

fn send_fin_packet(rust_tcp: &mut RustTcp, seqnum: u32, last_response: &[u8]) -> Vec<u8> {
    let mut response_fin: Vec<u8> = Vec::new();
    let fin_packet = build_fin_packet(&[], seqnum, last_response);
    rust_tcp.on_packet(&fin_packet, &mut response_fin).unwrap();

    response_fin
}

fn send_ack_packet(rust_tcp: &mut RustTcp, seqnum: u32, data: &[u8], ack_seqnum: u32) -> Vec<u8> {
    let mut response_data: Vec<u8> = Vec::new();
    let data_packet = build_ack_packet(data, seqnum, ack_seqnum);
    rust_tcp
        .on_packet(&data_packet, &mut response_data)
        .unwrap();

    response_data
}

fn build_fin_packet(payload: &[u8], seqnum: u32, response_syn: &[u8]) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    let (_, resp_tcphdr) = Ipv4Header::from_slice(&response_syn[..]).unwrap();
    let (resp_tcphdr, _) = TcpHeader::from_slice(resp_tcphdr).unwrap();

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
    .ack(resp_tcphdr.sequence_number + 1)
    .fin()
    .write(&mut packet, payload)
    .unwrap();

    packet
}

#[test]
fn close_server_connection_after_receiving_fin_packet() {
    const CLIENT_SEQNUM: u32 = 100;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = get_ack_seqnum(&resp_syn);
    let response_data = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

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

#[test]
fn send_second_packet_with_same_sequence_number_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = get_ack_seqnum(&resp_syn);
    let response_data1 = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);
    let response_data2 = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check responses
    let (_, tcphdr_slice1) = Ipv4Header::from_slice(&response_data1).unwrap();
    let (_, tcphdr_slice2) = Ipv4Header::from_slice(&response_data2).unwrap();
    let (tcphdr1, _) = TcpHeader::from_slice(tcphdr_slice1).unwrap();
    let (tcphdr2, _) = TcpHeader::from_slice(tcphdr_slice2).unwrap();

    assert_eq!(tcphdr1.rst, false);
    assert_eq!(tcphdr1.ack, true);
    assert_eq!(tcphdr1.acknowledgment_number, 104);

    assert_eq!(tcphdr2.rst, false);
    assert_eq!(tcphdr2.ack, true);
    assert_eq!(tcphdr2.acknowledgment_number, 104);

    assert_eq!(nbytes_read, 3);
    assert_eq!(&recv_buf[..3], &[1, 2, 3]);
}

#[test]
fn send_packet_with_sequence_number_higher_than_the_receive_window_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = get_ack_seqnum(&resp_syn);
    let response_data = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 300, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check response
    let (_, tcphdr_slice) = Ipv4Header::from_slice(&response_data).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_packet_bigger_than_the_receive_window_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB];
    let ack_seqnum = get_ack_seqnum(&resp_syn);
    let response_data = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check response
    let (_, tcphdr_slice) = Ipv4Header::from_slice(&response_data).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_data_with_max_u32_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 1;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let ack_seqnum = get_ack_seqnum(&resp_syn);
    let response_data = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check response
    let (_, tcphdr_slice) = Ipv4Header::from_slice(&response_data).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 4);
    assert_eq!(nbytes_read, 5);
}

#[test]
fn send_data_with_wrapped_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 5;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data1 = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let ack_seqnum = get_ack_seqnum(&resp_syn);
    let response_data1 = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data1, ack_seqnum);

    let seqnum = CLIENT_SEQNUM.wrapping_add(data1.len() as u32 + 1);
    let data2 = &[0x1, 0x2, 0x3];
    let ack_seqnum = get_ack_seqnum(&response_data1);
    let response_data2 = send_ack_packet(&mut rust_tcp, seqnum, data2, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check response
    let (_, tcphdr_slice2) = Ipv4Header::from_slice(&response_data2).unwrap();
    let (tcphdr2, _) = TcpHeader::from_slice(tcphdr_slice2).unwrap();

    assert_eq!(tcphdr2.rst, false);
    assert_eq!(tcphdr2.ack, true);
    assert_eq!(tcphdr2.acknowledgment_number, 3);
    assert_eq!(nbytes_read, 8);
}

#[test]
fn send_reset_when_receiving_ack_packet_on_closed_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let response_data = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, 300);

    // Check response
    let (_, tcphdr_slice) = Ipv4Header::from_slice(&response_data).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();
    let expected_seqnum = CLIENT_SEQNUM + 1 + data.len() as u32;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 300);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_packet_on_closed_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let response_data = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data);

    // Check response
    let (_, tcphdr_slice) = Ipv4Header::from_slice(&response_data).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();
    let expected_seqnum = CLIENT_SEQNUM + 1 + data.len() as u32;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 0);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

fn send_data_packet(rust_tcp: &mut RustTcp, seqnum: u32, data: &[u8]) -> Vec<u8> {
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
        22,     //destination
        seqnum, //seq
        10,     // windows size)
    )
    .write(&mut packet, payload)
    .unwrap();

    packet
}

#[test]
fn send_reset_when_receiving_bad_ack_seqnum_during_handshake() {
    let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let response_syn = receive_syn_packet(&mut rust_tcp, CLIENT_SEQNUM + 1);
    let ack_seqnum = get_ack_seqnum(&response_syn).wrapping_add(20000);
    let resp_ack = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, &[], ack_seqnum);

    let (_, tcphdr_slice) = Ipv4Header::from_slice(&resp_ack).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, ack_seqnum);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_bad_ack_during_handshake() {
    let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let _ = receive_syn_packet(&mut rust_tcp, CLIENT_SEQNUM + 1);
    let resp = receive_syn_packet(&mut rust_tcp, CLIENT_SEQNUM + 1);

    let (_, tcphdr_slice) = Ipv4Header::from_slice(&resp).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 0);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_bad_syn_during_handshake() {
    let mut rust_tcp = RustTcp::new(&Ipv4Addr::from([192, 168, 1, 2]));
    rust_tcp.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let resp_ack = send_ack_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, &[], 42);

    let (_, tcphdr_slice) = Ipv4Header::from_slice(&resp_ack).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 42);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_syn_packet_on_opening_active_connection() {
    use RustTcpMode::Active;

    let ip_client = Ipv4Addr::from([192, 168, 1, 1]);
    let mut client = RustTcp::new(&ip_client);

    let dst_ip = Ipv4Addr::from([192, 168, 1, 2]).octets();
    client.open(Active(dst_ip, 22), "client").unwrap();

    let mut response: Vec<u8> = Vec::new();
    client.on_user_event(&mut response).unwrap();

    let (iphdr, tcphdr_slice) = Ipv4Header::from_slice(&response).unwrap();
    let (tcphdr, payload) = TcpHeader::from_slice(tcphdr_slice).unwrap();
    let expected_resp_iphdr = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2]);

    assert_eq!(iphdr, expected_resp_iphdr);
    assert_eq!(tcphdr.source_port, 36000);
    assert_eq!(tcphdr.destination_port, 22);
    assert_eq!(tcphdr.syn, true);
    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, false);
    assert_eq!(payload, &[]);
}

#[test]
fn send_ack_packet_on_receiving_syn_ack_packet() {
    use RustTcpMode::{Active, Passive};

    let ip_client = Ipv4Addr::from([192, 168, 1, 1]);
    let ip_server = Ipv4Addr::from([192, 168, 1, 2]);
    let mut client = RustTcp::new(&ip_client);
    let mut server = RustTcp::new(&ip_server);

    let dst_ip = Ipv4Addr::from(ip_server).octets();
    client.open(Active(dst_ip, 22), "client").unwrap();
    server.open(Passive(22), "server").unwrap();

    let mut syn_request: Vec<u8> = Vec::new();
    let mut syn_ack_resp: Vec<u8> = Vec::new();

    client.on_user_event(&mut syn_request).unwrap();
    server.on_packet(&syn_request, &mut syn_ack_resp).unwrap();

    let mut ack_resp: Vec<u8> = Vec::new();
    client.on_packet(&syn_ack_resp, &mut ack_resp).unwrap();

    let (_, tcphdr_slice) = Ipv4Header::from_slice(&ack_resp).unwrap();
    let (tcphdr, payload) = TcpHeader::from_slice(tcphdr_slice).unwrap();

    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.syn, false);
    assert_eq!(tcphdr.rst, false);
    assert_eq!(payload, &[]);
}
