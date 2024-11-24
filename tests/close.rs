mod helpers;

use helpers::*;
use rusttcp::rusttcp::*;

#[test]
fn server_sends_a_ack_after_receiving_a_fin_packet() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let _ = server.open(RustTcpMode::Passive(PortNumber(22))).unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let response_fin = send_fin_to(&mut server, CLIENT_SEQNUM, &resp_syn);

    // Check response
    let (_, tcphdr, _) = extract_packet(&response_fin);

    assert_eq!(tcphdr.acknowledgment_number, 101);
    assert_eq!(tcphdr.ack, true);
}

#[test]
fn server_send_fin_packet_then_close_connection_after_receiving_fin_packet_from_client() {
    const CLIENT_SEQNUM: u32 = 100;

    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(10)
        .build();
    let fd = server.open(RustTcpMode::Passive(PortNumber(22))).unwrap();

    let resp_syn = do_server_handshake(&mut server, CLIENT_SEQNUM);
    let fin_resp = send_fin_to(&mut server, CLIENT_SEQNUM + 1, &resp_syn);

    let event1 = server.poll();
    server.close(fd);

    // Extract the FIN request to close the other half connection
    let (iphdr_fin, tcphdr_fin, _, _) = process_user_event_with_extract(&mut server);
    let ack_seqnum = seqnum_from(&fin_resp);

    // Send ACK for the FIN request
    send_ack_to(&mut server, CLIENT_SEQNUM + 1, &[], ack_seqnum);

    // Send a data packet to check that the connection has been removed
    // The server shall respond with a RESET packet
    let ack_seqnum = seqnum_from(&resp_syn) + 1;
    let response = send_ack_to(&mut server, CLIENT_SEQNUM + 1, &[], ack_seqnum);
    let (_, tcphdr_reset, _) = extract_packet(&response);

    let event2 = server.poll();

    assert_eq!(event1, TcpEvent::ConnectionClosing);
    assert_eq!(event2, TcpEvent::ConnectionClosed);

    assert_eq!(tcphdr_fin.fin, true);
    assert_eq!(tcphdr_fin.ack, true);
    assert_eq!(tcphdr_fin.acknowledgment_number, 102);
    assert_eq!(tcphdr_fin.source_port, 22);
    assert_eq!(tcphdr_fin.destination_port, 35000);

    assert_eq!(iphdr_fin.source, [192, 168, 1, 2]);
    assert_eq!(iphdr_fin.destination, [192, 168, 1, 1]);

    assert_eq!(tcphdr_reset.rst, true);
    assert_eq!(tcphdr_reset.ack, true);
}
