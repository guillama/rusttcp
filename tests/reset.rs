mod helpers;

use helpers::*;
use rusttcp::rusttcp::*;

#[test]
fn send_reset_when_receiving_ack_packet_on_closed_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2]).build();

    // No call to open() -> so connection is closed

    let data = &[0x1, 0x2, 0x3, 0x4, 0x5];
    let (iphdr, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, data, 300);

    let expected_seqnum = CLIENT_SEQNUM + 1 + data.len() as u32;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 300);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
    assert_eq!(tcphdr.source_port, 22);
    assert_eq!(tcphdr.destination_port, 35000);

    assert_eq!(iphdr.source, [192, 168, 1, 2]);
    assert_eq!(iphdr.destination, [192, 168, 1, 1]);
}

#[test]
fn send_reset_when_receiving_packet_on_closed_connection() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2]).build();

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
    let mut server = RustTcpBuilder::new([192, 168, 1, 2]).build();
    let _ = server.open(RustTcpMode::Passive(22)).unwrap();

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
    let mut server = RustTcpBuilder::new([192, 168, 1, 2]).build();
    let _ = server.open(RustTcpMode::Passive(22)).unwrap();

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
    let mut server = RustTcpBuilder::new([192, 168, 1, 2]).build();
    let _ = server.open(RustTcpMode::Passive(22)).unwrap();

    const CLIENT_SEQNUM: u32 = 100;
    let (_, tcphdr, _) = send_ack_with_extract_to(&mut server, CLIENT_SEQNUM + 1, &[], 42);
    let expected_seqnum = CLIENT_SEQNUM + 1;

    assert_eq!(tcphdr.rst, true);
    assert_eq!(tcphdr.ack, true);
    assert_eq!(tcphdr.sequence_number, 42);
    assert_eq!(tcphdr.acknowledgment_number, expected_seqnum);
}

#[test]
fn send_reset_packet_after_receiving_ack_instead_of_syn_ack_packet() {
    let mut client = RustTcpBuilder::new([192, 168, 1, 1])
        .sequence_number(100)
        .build();
    let _ = client
        .open(RustTcpMode::Active([192, 168, 1, 2], 22))
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
fn server_closes_connection_after_receiving_a_reset_from_client() {
    let mut server = RustTcpBuilder::new([192, 168, 1, 2]).build();
    let _ = server.open(RustTcpMode::Passive(22));

    // 3-way handshake
    let _ = do_server_handshake(&mut server, 100);

    // Send reset
    let reset_packet = build_reset_packet();
    let mut response = [0; 1400];
    server.on_packet(&reset_packet, &mut response).unwrap();

    let event = server.poll();

    assert_eq!(event, TcpEvent::ConnectionClosed);
}
