mod helpers;

use helpers::*;
use rusttcp::rusttcp::*;

#[test]
fn poll_returns_event_to_the_server_after_client_has_sent_user_data() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, fd_server, _) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
    client.write(fd_client, data).unwrap();

    let client_packet = process_user_event(&mut client);
    let mut response = [0; 1400];
    server.on_packet(&client_packet, &mut response).unwrap();

    let event1 = server.poll();

    let mut recv_buf = [0; 1504];
    let read_size = server.read(fd_server, &mut recv_buf).unwrap();

    let event2 = server.poll();

    assert_eq!(event1, TcpEvent::DataReceived(data.len()));
    assert_eq!(read_size, data.len());
    assert_eq!(&recv_buf[..read_size], data);
    assert_eq!(event2, TcpEvent::NoEvent);
}

#[test]
fn poll_returns_event_to_the_server_after_the_receiving_buffer_has_been_full() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, fd_server, _) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    client.write(fd_client, data).unwrap();

    let client_packet1 = process_user_event(&mut client);
    let mut response = [0; 1400];
    server.on_packet(&client_packet1, &mut response).unwrap();
    let event = server.poll();

    let mut recv_buf = [0; 1504];
    let read_size = server.read(fd_server, &mut recv_buf).unwrap();

    assert_eq!(event, TcpEvent::DataReceived(WINDOW_SIZE as usize));
    assert_eq!(read_size, WINDOW_SIZE as usize);
}

#[test]
fn poll_doesnt_return_event_to_the_server_until_client_has_sent_all_of_his_user_data() {
    const WINDOW_SIZE: u16 = 10;

    let mut client = RustTcpBuilder::new([192, 168, 1, 1].into()).build();
    let mut server = RustTcpBuilder::new([192, 168, 1, 2].into())
        .window_size(WINDOW_SIZE)
        .build();

    // 3-way handshake
    let (fd_client, fd_server, _) = open_and_handshake(&mut client, &mut server);

    // Send data
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    client.write(fd_client, data).unwrap();
    let client_packet1 = process_user_event(&mut client);

    let mut server_ack = [0; 1400];
    server.on_packet(&client_packet1, &mut server_ack).unwrap();
    let _ = server.poll();

    let mut recv_buf = [0; 1504];
    let read_size1 = server.read(fd_server, &mut recv_buf[0..]).unwrap();

    let client_packet2 = process_user_event(&mut client);
    let mut response = [0; 1400];
    server.on_packet(&client_packet2, &mut response).unwrap();
    let event2 = server.poll();

    let read_size2 = server.read(fd_server, &mut recv_buf[read_size1..]).unwrap();

    assert_eq!(event2, TcpEvent::DataReceived(data.len() - read_size1));
    assert_eq!(read_size2, data.len() - read_size1);
    assert_eq!(&recv_buf[..data.len()], data);
}
