use std::sync::{Arc, Mutex};

mod helpers;

use helpers::*;
use rusttcp::{fake_timer::Timer, rusttcp::RustTcpBuilder};

#[test]
fn client_retransmits_data_by_doubling_the_timeout_between_successive_retransmissions() {
    const WINDOW_SIZE: u16 = 10;

    let fake_timer = Arc::new(Mutex::new(Timer::now()));
    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into())
        .timer(fake_timer.clone())
        .tcp_max_retries(5)
        .build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, _, _) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5];
    client.write(fd_client, data).unwrap();
    let client_packet1 = process_user_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(199);
    let client_packet_not_retransmitted = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(1); // timeout +200ms
    let client_packet_retransmitted1 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(399);
    let client_packet_not_retransmitted1 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(1); // timeout +400ms
    let client_packet_retransmitted2 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(799);
    let client_packet_not_retransmitted2 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(1); // timeout +800ms
    let client_packet_retransmitted3 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(1599);
    let client_packet_not_retransmitted3 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(1); // timeout +1600ms
    let client_packet_retransmitted4 = process_timeout_event(&mut client);
    dbg!(line!());

    fake_timer.lock().unwrap().add_millisecs(3199);
    let client_packet_not_retransmitted4 = process_timeout_event(&mut client);
    dbg!(line!());

    fake_timer.lock().unwrap().add_millisecs(1); // timeout +3200ms
    let client_packet_retransmitted5 = process_timeout_event(&mut client);

    dbg!(line!());
    fake_timer.lock().unwrap().add_millisecs(6400); // timeout +6400ms
    let client_packet_retransmitted6 = process_timeout_event(&mut client);

    dbg!(line!());

    // Check that the connection has been removed
    client.write(fd_client, data).unwrap_err();

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
    assert_eq!(client_packet1, client_packet_retransmitted2);
    assert_eq!(client_packet1, client_packet_retransmitted3);
    assert_eq!(client_packet1, client_packet_retransmitted4);
    assert_eq!(client_packet1, client_packet_retransmitted5);
    assert_eq!(client_packet_retransmitted6, Vec::new());
}

#[test]
fn client_resets_its_timer_after_receiving_a_response() {
    const WINDOW_SIZE: u16 = 5;

    let fake_timer = Arc::new(Mutex::new(Timer::now()));
    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into())
        .timer(fake_timer.clone())
        .tcp_max_retries(5)
        .build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, _, _) = open_and_handshake(&mut client, &mut server);

    // Send data bigger than the sending window size
    let data = &[1, 2, 3, 4, 5, 6, 7, 8];
    client.write(fd_client, data).unwrap();
    let client_packet1 = process_user_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(200);
    let client_packet_retransmitted1 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(400);
    let client_packet_retransmitted2 = process_timeout_event(&mut client);

    let mut server_ack = [0; 1400];
    let mut response = [0; 1400];
    server.on_packet(&client_packet1, &mut server_ack).unwrap();
    client.on_packet(&server_ack, &mut response).unwrap();

    let client_packet2 = process_user_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(200);
    let client_packet_retransmitted3 = process_timeout_event(&mut client);

    fake_timer.lock().unwrap().add_millisecs(400);
    let client_packet_retransmitted4 = process_timeout_event(&mut client);

    assert_eq!(client_packet1.len(), 45);
    assert_eq!(client_packet_retransmitted1.len(), 45);
    assert_eq!(client_packet_retransmitted2.len(), 45);

    assert_eq!(client_packet2.len(), 43);
    assert_eq!(client_packet_retransmitted3.len(), 43);
    assert_eq!(client_packet_retransmitted4.len(), 43);

    assert_eq!(client_packet1, client_packet_retransmitted1);
    assert_eq!(client_packet1, client_packet_retransmitted2);

    assert_eq!(client_packet2, client_packet_retransmitted3);
    assert_eq!(client_packet2, client_packet_retransmitted4);
}
