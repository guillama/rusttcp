extern crate etherparse;

mod helpers;

use etherparse::{Ipv4Header, TcpHeader};
use helpers::*;
use rusttcp::connection::{RustTcp, RustTcpMode, TcpEvent};
use rusttcp::fake_timer::*;
use std::cell::RefCell;
use std::rc::Rc;
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

#[test]
fn send_ack_with_correct_seqnum_after_a_3way_handshake_and_receiving_data() {
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(10);
    server.open(RustTcpMode::Passive(22), "conn1").unwrap();

    // Send SYN packet
    const CLIENT_SEQNUM: u32 = 100;
    let response_syn = receive_syn(&mut server, CLIENT_SEQNUM);

    // Send ACK + DATA packet
    let acknum = seqnum_from(&response_syn) + 1;
    let seqnum = CLIENT_SEQNUM + 1;
    let resp_ack = send_ack_to(&mut server, seqnum, &[], acknum);
    let (_, tcphdr, payload) = send_ack_with_extract_to(&mut server, seqnum, &[1, 2, 3], acknum);

    assert_eq!(resp_ack, &[]);
    assert_eq!(payload, []);
    assert_eq!(tcphdr.acknowledgment_number, 104);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.syn, false);
    assert_eq!(tcphdr.rst, false);
}

#[test]
fn send_fin_packet_close_server_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(10);
    server.open(RustTcpMode::Passive(22), "conn1").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let response_data = send_ack_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let seqnum = CLIENT_SEQNUM + 1 + (data.len() as u32);
    let response_fin = send_fin(&mut server, seqnum, &response_data);

    // Check responses
    let (_, tcphdr, _) = extract_packet(&response_fin);

    assert_eq!(tcphdr.acknowledgment_number, 104);
    assert_eq!(tcphdr.ack, true);
}

#[test]
fn close_server_connection_after_receiving_fin_packet() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(10);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);

    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let response_data = send_ack_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

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

    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(10);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr1, _) =
        send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);
    let (_, tcphdr2, _) =
        send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

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

    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr, _) =
        send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 300, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_packet_bigger_than_the_receive_window_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_data_with_max_u32_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 1;

    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(10);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let ack_seqnum = seqnum_from(&resp_syn);
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read("conn2", &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 4);
    assert_eq!(nbytes_read, 5);
}

#[test]
fn send_data_with_wrapped_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 5;

    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(10);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data1 = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let ack_seqnum = seqnum_from(&resp_syn);
    let response_data = send_ack_to(&mut server, CLIENT_SEQNUM + 1, data1, ack_seqnum);

    let seqnum = CLIENT_SEQNUM.wrapping_add(data1.len() as u32 + 1);
    let data2 = &[0x1, 0x2, 0x3];
    let ack_seqnum = seqnum_from(&response_data);
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, seqnum, data2, ack_seqnum);

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
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, 300);

    let expected_seqnum = CLIENT_SEQNUM + 1 + data.len() as u32;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 300);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_packet_on_closed_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcp::new([192, 168, 1, 2]);

    // No call to open()

    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];

    // Check response
    let (_, tcphdr, _) = send_data_to(&mut server, data, CLIENT_SEQNUM + 1);
    let expected_seqnum = CLIENT_SEQNUM + 1 + data.len() as u32;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 0);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_bad_ack_seqnum_during_handshake() {
    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 101;
    let response_syn = receive_syn(&mut server, CLIENT_SEQNUM);
    let ack_seqnum = seqnum_from(&response_syn).wrapping_add(20000);
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM, &[], ack_seqnum);

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, ack_seqnum);
    assert_eq!(tcphdr.acknowledgment_number, CLIENT_SEQNUM);
}

#[test]
fn send_reset_when_receiving_bad_ack_during_handshake() {
    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let _ = receive_syn(&mut server, CLIENT_SEQNUM + 1);
    let reset_resp = receive_syn(&mut server, CLIENT_SEQNUM + 1);

    let (_, tcphdr, _) = extract_packet(&reset_resp);
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 0);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_when_receiving_bad_syn_during_handshake() {
    let mut server = RustTcp::new([192, 168, 1, 2]);
    server.open(RustTcpMode::Passive(22), "conn2").unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, &[], 42);
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 42);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_syn_packet_on_opening_active_connection() {
    let mut client = RustTcp::new([192, 168, 1, 1]);
    client
        .open(RustTcpMode::Active([192, 168, 1, 2], 22), "client")
        .unwrap();

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
    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]);
    client
        .open(RustTcpMode::Active([192, 168, 1, 2], 22), "client")
        .unwrap();
    server.open(RustTcpMode::Passive(22), "server").unwrap();

    let syn_request = process_user_event(&mut client);
    let syn_ack_resp = on_packet_event(&mut server, &syn_request);

    let (_, tcphdr, payload) = on_packet_event_with_extract(&mut client, &syn_ack_resp);
    let expected_ack = seqnum_from(&syn_ack_resp) + 1;

    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, expected_ack);
    assert_eq!(tcphdr.syn, false);
    assert_eq!(tcphdr.rst, false);
    assert_eq!(payload, &[]);
}

#[test]
fn send_reset_packet_after_receiving_ack_instead_of_syn_ack_packet() {
    let mut client = RustTcp::new([192, 168, 1, 1]).sequence_number(100);
    client
        .open(RustTcpMode::Active([192, 168, 1, 2], 22), "client")
        .unwrap();

    let _ = process_user_event(&mut client);
    let ack_packet = build_ack_packet_to_client(&[], 300, 100);

    let (_, tcphdr, payload) = on_packet_event_with_extract(&mut client, &ack_packet);

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, seqnum_from(&ack_packet));
    assert_eq!(tcphdr.syn, false);
    assert_eq!(payload, &[]);
}

#[test]
fn send_user_data_with_length_within_the_window_size() {
    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(10);

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
fn send_user_data_with_length_bigger_than_the_window_size() {
    const WINDOW_SIZE: u16 = 5;
    const CLIENT_SEQNUM: u32 = 500;

    let mut client = RustTcp::new([192, 168, 1, 1]).sequence_number(CLIENT_SEQNUM);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let expected_acknum = do_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8];
    client.write("client", data).unwrap();

    let (iphdr1, tcphdr1, payload1, next_data_size1) = process_user_event_with_extract(&mut client);
    let payload_len1 = TcpHeader::MIN_LEN + WINDOW_SIZE as usize;
    let expected_iphdr1 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len1);

    let (iphdr2, tcphdr2, payload2, next_data_size2) = process_user_event_with_extract(&mut client);
    let payload_len2 = TcpHeader::MIN_LEN + (data.len() - WINDOW_SIZE as usize);
    let expected_iphdr2 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len2);

    assert_eq!(next_data_size1, 3);
    assert_eq!(iphdr1, expected_iphdr1);
    assert_eq!(payload1, &[1, 2, 3, 4, 5]);
    assert_eq!(tcphdr1.sequence_number, 501);
    assert_eq!(tcphdr1.ack, true);
    assert_eq!(tcphdr1.acknowledgment_number, expected_acknum);

    assert_eq!(next_data_size2, 0);
    assert_eq!(iphdr2, expected_iphdr2);
    assert_eq!(payload2, &[6, 7, 8]);
    assert_eq!(tcphdr2.sequence_number, 506);
    assert_eq!(tcphdr2.ack, true);
    assert_eq!(tcphdr2.acknowledgment_number, expected_acknum);
}

#[test]
fn send_several_user_data_within_the_window_size() {
    const WINDOW_SIZE: u16 = 5;
    const CLIENT_SEQNUM: u32 = 20;

    let mut client = RustTcp::new([192, 168, 1, 1]).sequence_number(CLIENT_SEQNUM);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send data
    let data1 = &[1, 2, 3, 4, 5];
    client.write("client", data1).unwrap();

    let data2 = &[5, 6, 7];
    client.write("client", data2).unwrap();

    let (iphdr1, tcphdr1, payload1, next_data_size1) = process_user_event_with_extract(&mut client);
    let payload_len1 = TcpHeader::MIN_LEN + data1.len();
    let expected_iphdr1 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len1);

    let (iphdr2, tcphdr2, payload2, next_data_size2) = process_user_event_with_extract(&mut client);
    let payload_len2 = TcpHeader::MIN_LEN + data2.len();
    let expected_iphdr2 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len2);

    assert_eq!(next_data_size1, 0);
    assert_eq!(iphdr1, expected_iphdr1);
    assert_eq!(payload1, data1);
    assert_eq!(tcphdr1.sequence_number, CLIENT_SEQNUM + 1);

    assert_eq!(next_data_size2, 0);
    assert_eq!(iphdr2, expected_iphdr2);
    assert_eq!(payload2, data2);

    let expected_seqnum = CLIENT_SEQNUM + 1 + data1.len() as u32;
    assert_eq!(tcphdr2.sequence_number, expected_seqnum);
}

#[test]
fn send_several_user_data_with_length_bigger_than_the_window_size() {
    const WINDOW_SIZE: u16 = 5;

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send data
    let data1 = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    client.write("client", data1).unwrap();

    let data2 = &[12, 13, 14, 15, 16, 17, 18];
    client.write("client", data2).unwrap();

    let (_, _, payload1, next_data_size1) = process_user_event_with_extract(&mut client);
    let (_, _, payload2, next_data_size2) = process_user_event_with_extract(&mut client);
    let (_, _, payload3, next_data_size3) = process_user_event_with_extract(&mut client);
    let (_, _, payload4, next_data_size4) = process_user_event_with_extract(&mut client);
    let (_, _, payload5, next_data_size5) = process_user_event_with_extract(&mut client);

    assert_eq!(next_data_size1, 6);
    assert_eq!(payload1, &[1, 2, 3, 4, 5]);

    assert_eq!(next_data_size2, 1);
    assert_eq!(payload2, &[6, 7, 8, 9, 10]);

    assert_eq!(next_data_size3, 0);
    assert_eq!(payload3, &[11]);

    assert_eq!(next_data_size4, 2);
    assert_eq!(payload4, &[12, 13, 14, 15, 16]);

    assert_eq!(next_data_size5, 0);
    assert_eq!(payload5, &[17, 18]);
}

#[test]
fn server_window_size_is_updated_after_receiving_data() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send client data
    let data = &[1, 2, 3, 4, 5, 6];
    client.write("client", data).unwrap();
    let client_data = process_user_event(&mut client);

    let mut response = Vec::new();
    server.on_packet(&client_data, &mut response).unwrap();
    let (_, tcphdr, _) = extract_packet(&response);

    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.window_size, WINDOW_SIZE - data.len() as u16);
}

#[test]
fn server_window_size_is_updated_after_receiving_data_length_equal_to_window_size() {
    const WINDOW_SIZE: u16 = 5;

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send client data
    let data = &[1, 2, 3, 4, 5];
    client.write("client", data).unwrap();
    let client_data = process_user_event(&mut client);

    let mut response = Vec::new();
    server.on_packet(&client_data, &mut response).unwrap();
    let (_, tcphdr, _) = extract_packet(&response);

    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.window_size, WINDOW_SIZE - data.len() as u16);
}

#[test]
fn poll_returns_event_to_the_server_after_client_has_sent_user_data() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
    client.write("client", data).unwrap();

    let client_packet = process_user_event(&mut client);
    server.on_packet(&client_packet, &mut Vec::new()).unwrap();

    let event1 = server.poll().unwrap();

    let mut recv_buf = [0; 1504];
    let read_size = server.read("server", &mut recv_buf).unwrap();

    let event2 = server.poll().unwrap();

    assert_eq!(event1, TcpEvent::DataReceived(data.len()));
    assert_eq!(read_size, data.len());
    assert_eq!(&recv_buf[..read_size], data);
    assert_eq!(event2, TcpEvent::NoEvent);
}

#[test]
fn poll_returns_event_to_the_server_after_the_receiving_buffer_has_been_full() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    client.write("client", data).unwrap();

    let client_packet1 = process_user_event(&mut client);
    server.on_packet(&client_packet1, &mut Vec::new()).unwrap();
    let event = server.poll().unwrap();

    let mut recv_buf = [0; 1504];
    let read_size = server.read("server", &mut recv_buf).unwrap();

    assert_eq!(event, TcpEvent::DataReceived(WINDOW_SIZE as usize));
    assert_eq!(read_size, WINDOW_SIZE as usize);
}

#[test]
fn poll_doesnt_return_event_to_the_server_until_client_has_sent_all_of_his_user_data() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcp::new([192, 168, 1, 1]);
    let mut server = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    client.write("client", data).unwrap();
    let client_packet1 = process_user_event(&mut client);

    let mut server_ack = Vec::new();
    server.on_packet(&client_packet1, &mut server_ack).unwrap();
    let _ = server.poll().unwrap();

    let mut recv_buf = [0; 1504];
    let read_size1 = server.read("server", &mut recv_buf[0..]).unwrap();

    let client_packet2 = process_user_event(&mut client);
    server.on_packet(&client_packet2, &mut Vec::new()).unwrap();
    let event2 = server.poll().unwrap();

    let read_size2 = server.read("server", &mut recv_buf[read_size1..]).unwrap();

    assert_eq!(event2, TcpEvent::DataReceived(data.len() - read_size1));
    assert_eq!(read_size2, data.len() - read_size1);
    assert_eq!(&recv_buf[..data.len()], data);
}

#[test]
fn client_retransmits_data_by_doubling_the_timeout_between_successive_retransmissions() {
    const WINDOW_SIZE: u16 = 10;

    let fake_timer = Rc::new(RefCell::new(Timer::now()));
    let mut client: RustTcp = RustTcp::new([192, 168, 1, 1]).timer(fake_timer.clone());
    let mut server: RustTcp = RustTcp::new([192, 168, 1, 2]).window_size(WINDOW_SIZE);

    // 3-way handshake
    let _ = do_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5];
    client.write("client", data).unwrap();
    let client_packet1 = process_user_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(199);
    let client_packet_not_retransmitted = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(1); // timeout +200ms
    let client_packet_retransmitted1 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(399);
    let client_packet_not_retransmitted1 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(1); // timeout +400ms
    let client_packet_retransmitted2 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(799);
    let client_packet_not_retransmitted2 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(1); // timeout +800ms
    let client_packet_retransmitted3 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(1599);
    let client_packet_not_retransmitted3 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(1); // timeout +1600ms
    let client_packet_retransmitted4 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(3199);
    let client_packet_not_retransmitted4 = process_timeout_event(&mut client);

    fake_timer.borrow_mut().add_millisecs(1); // timeout +3200ms
    let client_packet_retransmitted5 = process_timeout_event(&mut client);

    assert_eq!(client_packet1.len(), 45);
    assert_eq!(client_packet_not_retransmitted.len(), 0);
    assert_eq!(client_packet_retransmitted1.len(), 45);
    assert_eq!(client_packet_not_retransmitted1.len(), 0);
    assert_eq!(client_packet_retransmitted2.len(), 45);
    assert_eq!(client_packet_not_retransmitted2.len(), 0);
    assert_eq!(client_packet_retransmitted3.len(), 45);
    assert_eq!(client_packet_not_retransmitted3.len(), 0);
    assert_eq!(client_packet_retransmitted4.len(), 45);
    assert_eq!(client_packet_not_retransmitted4.len(), 0);
    assert_eq!(client_packet_retransmitted5.len(), 45);
    assert_eq!(client_packet1, client_packet_retransmitted1);
    assert_eq!(client_packet_retransmitted1, client_packet_retransmitted2);
    assert_eq!(client_packet_retransmitted2, client_packet_retransmitted3);
    assert_eq!(client_packet_retransmitted3, client_packet_retransmitted4);
    assert_eq!(client_packet_retransmitted4, client_packet_retransmitted5);
}
