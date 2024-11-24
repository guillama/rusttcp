mod helpers;

use etherparse::{Ipv4Header, TcpHeader};
use helpers::*;
use rusttcp::rusttcp::*;

#[test]
fn send_syn_ack_with_correct_flags_and_seqnums_after_receiving_syn_packet() {
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into()).build();
    let _ = server.open(RustTcpMode::Passive(22)).unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let response = receive_syn(&mut server, CLIENT_SEQNUM);

    // Check ACK response
    let expected_iphdr = build_ipv4_header([192, 168, 1, 2], [192, 168, 1, 1], TcpHeader::MIN_LEN);
    let (iphdr, tcphdr, _) = extract_packet(&response);

    assert_eq!(response.len(), Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN);
    assert_eq!(iphdr, expected_iphdr);
    assert_eq!(tcphdr.source_port, 22);
    assert_eq!(tcphdr.syn, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.acknowledgment_number, CLIENT_SEQNUM + 1);
    assert_eq!(tcphdr.window_size, RustTcp::DEFAULT_WINDOW_SIZE);
}

#[test]
fn send_ack_with_correct_seqnum_after_a_3way_handshake_and_receiving_data() {
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let _ = server.open(RustTcpMode::Passive(22)).unwrap();

    // Send SYN packet
    const CLIENT_SEQNUM: u32 = 100;
    let response_syn = receive_syn(&mut server, CLIENT_SEQNUM);

    // Send ACK packet
    let acknum = seqnum_from(&response_syn) + 1;
    let seqnum = CLIENT_SEQNUM + 1;

    let resp_ack = send_ack_to(&mut server, seqnum, &[], acknum);

    // Send data packet
    let (_, tcphdr, payload) = send_ack_with_extract_to(&mut server, seqnum, &[1, 2, 3], acknum);

    assert_eq!(resp_ack, &[]);
    assert_eq!(payload, []);
    assert_eq!(tcphdr.acknowledgment_number, 104);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.syn, false);
    assert_eq!(tcphdr.rst, false);
}

#[test]
fn send_syn_packet_on_opening_active_connection() {
    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let _ = client
        .open(RustTcpMode::Active([192, 168, 1, 2].into(), 22))
        .unwrap();

    let (iphdr, tcphdr, payload, _) = process_user_event_with_extract(&mut client);
    let expected_iphdr = build_ipv4_header([192, 168, 1, 1], [192, 168, 1, 2], TcpHeader::MIN_LEN);

    assert_eq!(iphdr, expected_iphdr);
    assert_eq!(tcphdr.destination_port, 22);
    assert_eq!(tcphdr.syn, true);
    assert_eq!(tcphdr.rst, false);
    assert_eq!(tcphdr.ack, false);
    assert_eq!(payload, &[]);
}

#[test]
fn send_ack_packet_after_receiving_syn_ack_packet() {
    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into()).build();
    let _ = client
        .open(RustTcpMode::Active([192, 168, 1, 2].into(), 22))
        .unwrap();
    let _ = server.open(RustTcpMode::Passive(22)).unwrap();

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
