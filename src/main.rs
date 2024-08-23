mod connection;
mod errors;
mod packets;

extern crate tun;

use connection::RustTcp;

use crate::errors::RustTcpError;

use std::env;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

const TUN_HEADER_SIZE: usize = 4;
const BUFF_MAX_SIZE: usize = 1504;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("[Usage]: {} [ipaddress]", args[0]);
    }

    let server_ipaddr: Ipv4Addr = args[1].parse().expect("Bad IPv4 address;");
    let mut config = tun::Configuration::default();
    config.address(server_ipaddr).netmask(24).up();

    let mut iface = tun::create(&config).expect("Failed to create device.");
    let mut rust_tcp = RustTcp::new(&server_ipaddr);

    rust_tcp.open(22, "conn1");

    println!("Waiting packets on address : {server_ipaddr}");

    loop {
        let mut request: Vec<u8> = vec![0u8; BUFF_MAX_SIZE];

        match iface.read(&mut request) {
            Ok(bytes_read) => request.truncate(bytes_read),
            Err(e) => {
                eprintln!("Failed to read request : {e}");
                thread::sleep(Duration::from_secs(1)); // avoid being flooded by errors
                continue;
            }
        };

        // Copy TUN header to the response vector
        let mut response: Vec<u8> = Vec::new();
        response.extend(request.iter().take(TUN_HEADER_SIZE));

        let ipv4_request = &request[TUN_HEADER_SIZE..];
        if let Err(e) = rust_tcp.on_request(ipv4_request, &mut response) {
            eprintln!("Failed to send answer : {e}");
        }

        match iface.write_all(&response) {
            Ok(_) => (),
            Err(e) => eprintln!("Failed to send answer : {e}"),
        };
    }
}
