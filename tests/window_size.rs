extern crate etherparse;

mod helpers;

use ctor::ctor;
use env_logger::Builder;
use etherparse::{Ipv4Header, TcpHeader};
use helpers::*;
use log::LevelFilter;
use rusttcp::rusttcp::*;
use std::io::Write;
use std::path::Path;
use std::u32::MAX;

#[ctor]
fn log_init() {
    Builder::new()
        .filter_level(LevelFilter::Error)
        .format(|buf, record| {
            let filename = Path::new(record.file().unwrap_or_default())
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            writeln!(
                buf,
                "[{:4}] [{:13}] [l.{:03}]: {}",
                record.level(),
                filename,
                record.line().unwrap_or_default(),
                record.args()
            )
        })
        .init();
}

#[test]
fn send_second_packet_with_same_sequence_number_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let fd = server.open(RustTcpMode::Passive(22)).unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[1, 2, 3];
    let ack_seqnum = seqnum_from(&resp_syn) + 1;
    let (_, tcphdr1, _) =
        send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);
    let (_, tcphdr2, _) =
        send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let read_size: usize = server.read(fd, &mut recv_buf).unwrap();

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

    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let fd = server.open(RustTcpMode::Passive(22)).unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let ack_seqnum = seqnum_from(&resp_syn) + 1;
    let data = &[1, 2, 3];
    let (_, tcphdr, _) =
        send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 300, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read(fd, &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_packet_bigger_than_the_receive_window_is_not_acknowledged() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let fd = server.open(RustTcpMode::Passive(22)).unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB];
    let ack_seqnum = seqnum_from(&resp_syn) + 1;
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read(fd, &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(nbytes_read, 0);
}

#[test]
fn send_data_with_max_u32_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 1;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let fd = server.open(RustTcpMode::Passive(22)).unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);

    let ack_seqnum = seqnum_from(&resp_syn) + 1;
    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read(fd, &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 4);
    assert_eq!(nbytes_read, 5);
}

#[test]
fn send_data_with_wrapped_sequence_number_is_acknowledged() {
    const CLIENT_SEQNUM: u32 = MAX - 5;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let fd = server.open(RustTcpMode::Passive(22)).unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);

    let ack_seqnum = seqnum_from(&resp_syn) + 1;
    let data1 = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let response_data = send_ack_to(&mut server, CLIENT_SEQNUM + 1, data1, ack_seqnum);

    let ack_seqnum = seqnum_from(&response_data);
    let seqnum = CLIENT_SEQNUM.wrapping_add(data1.len() as u32 + 1);
    let data2 = &[0x1, 0x2, 0x3];
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, seqnum, data2, ack_seqnum);

    let mut recv_buf = [0; 1504];
    let nbytes_read: usize = server.read(fd, &mut recv_buf).unwrap();

    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, 3);
    assert_eq!(nbytes_read, 8);
}

#[test]
fn send_user_data_with_length_within_the_window_size() {
    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();

    // 3-way handshake
    let (fd_client, _, expected_acknum) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6];
    client.write(fd_client, data).unwrap();

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

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into())
        .sequence_number(CLIENT_SEQNUM)
        .build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, _, expected_acknum) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8];
    client.write(fd_client, data).unwrap();

    let (iphdr1, tcphdr1, payload1, send_size1) = process_user_event_with_extract(&mut client);
    let payload_len1 = TcpHeader::MIN_LEN + WINDOW_SIZE as usize;
    let expected_iphdr1 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len1);

    let (iphdr2, tcphdr2, payload2, send_size2) = process_user_event_with_extract(&mut client);
    let payload_len2 = TcpHeader::MIN_LEN + (data.len() - WINDOW_SIZE as usize);
    let expected_iphdr2 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len2);

    assert_eq!(send_size1, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 5);
    assert_eq!(iphdr1, expected_iphdr1);
    assert_eq!(payload1, &[1, 2, 3, 4, 5]);
    assert_eq!(tcphdr1.sequence_number, 501);
    assert_eq!(tcphdr1.ack, true);
    assert_eq!(tcphdr1.acknowledgment_number, expected_acknum);

    assert_eq!(send_size2, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 3);
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

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into())
        .sequence_number(CLIENT_SEQNUM)
        .build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, _, _) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data1 = &[1, 2, 3, 4, 5];
    client.write(fd_client, data1).unwrap();

    let data2 = &[5, 6, 7];
    client.write(fd_client, data2).unwrap();

    let (iphdr1, tcphdr1, payload1, send_size1) = process_user_event_with_extract(&mut client);
    let payload_len1 = TcpHeader::MIN_LEN + data1.len();
    let expected_iphdr1 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len1);

    let (iphdr2, tcphdr2, payload2, send_size2) = process_user_event_with_extract(&mut client);
    let payload_len2 = TcpHeader::MIN_LEN + data2.len();
    let expected_iphdr2 = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], payload_len2);

    assert_eq!(send_size1, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 5);
    assert_eq!(iphdr1, expected_iphdr1);
    assert_eq!(payload1, data1);
    assert_eq!(tcphdr1.sequence_number, CLIENT_SEQNUM + 1);

    assert_eq!(send_size2, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 3);
    assert_eq!(iphdr2, expected_iphdr2);
    assert_eq!(payload2, data2);

    let expected_seqnum = CLIENT_SEQNUM + 1 + data1.len() as u32;
    assert_eq!(tcphdr2.sequence_number, expected_seqnum);
}

#[test]
fn send_several_user_data_with_length_bigger_than_the_window_size() {
    const WINDOW_SIZE: u16 = 5;

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, _, _) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data1 = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    client.write(fd_client, data1).unwrap();

    let data2 = &[12, 13, 14, 15, 16, 17, 18];
    client.write(fd_client, data2).unwrap();

    let (_, _, payload1, send_size1) = process_user_event_with_extract(&mut client);
    let (_, _, payload2, send_size2) = process_user_event_with_extract(&mut client);
    let (_, _, payload3, send_size3) = process_user_event_with_extract(&mut client);
    let (_, _, payload4, send_size4) = process_user_event_with_extract(&mut client);
    let (_, _, payload5, send_size5) = process_user_event_with_extract(&mut client);

    assert_eq!(send_size1, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 5);
    assert_eq!(payload1, &[1, 2, 3, 4, 5]);

    assert_eq!(send_size2, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 5);
    assert_eq!(payload2, &[6, 7, 8, 9, 10]);

    assert_eq!(send_size3, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 1);
    assert_eq!(payload3, &[11]);

    assert_eq!(send_size4, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 5);
    assert_eq!(payload4, &[12, 13, 14, 15, 16]);

    assert_eq!(send_size5, Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN + 2);
    assert_eq!(payload5, &[17, 18]);
}

#[test]
fn server_window_size_is_updated_after_receiving_data() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, _, _) = open_and_handshake(&mut client, &mut server);

    // Send client data
    let data = &[1, 2, 3, 4, 5, 6];
    client.write(fd_client, data).unwrap();
    let client_data = process_user_event(&mut client);

    let mut response = [0; 1400];
    server.on_packet(&client_data, &mut response).unwrap();
    let (_, tcphdr, _) = extract_packet(&response);

    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.window_size, WINDOW_SIZE - data.len() as u16);
}

#[test]
fn server_window_size_is_updated_after_receiving_data_length_equal_to_window_size() {
    const WINDOW_SIZE: u16 = 5;

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, _, _) = open_and_handshake(&mut client, &mut server);

    // Send client data
    let data = &[1, 2, 3, 4, 5];
    client.write(fd_client, data).unwrap();
    let client_data = process_user_event(&mut client);

    let mut response = [0; 1400];
    server.on_packet(&client_data, &mut response).unwrap();
    let (_, tcphdr, _) = extract_packet(&response);

    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.window_size, 0);
}
