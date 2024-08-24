extern crate etherparse;

use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
use rusttcp::connection::*;
use std::{net::Ipv4Addr, u32::MAX};

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

#[test]
fn send_second_packet_with_same_sequence_number_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let server_ip = Ipv4Addr::from([192, 168, 1, 2]);
    let mut rust_tcp = RustTcp::new(&server_ip);

    rust_tcp.open(22, "conn2");

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let response_data1 = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, &resp_syn);
    let response_data2 = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, &resp_syn);

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

    rust_tcp.open(22, "conn2");

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let response_data = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 300, data, &resp_syn);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check responses
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

    rust_tcp.open(22, "conn2");

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB];
    let response_data = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, &resp_syn);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check responses
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

    rust_tcp.open(22, "conn2");

    let resp_syn = do_handshake(&mut rust_tcp, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let response_data = send_data_packet(&mut rust_tcp, CLIENT_SEQNUM + 1, data, &resp_syn);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = rust_tcp.read("conn2", &mut recv_buf).unwrap();

    // Check responses
    let (_, tcphdr_slice) = Ipv4Header::from_slice(&response_data).unwrap();
    let (tcphdr, _) = TcpHeader::from_slice(tcphdr_slice).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 4);
    assert_eq!(nbytes_read, 5);
}
