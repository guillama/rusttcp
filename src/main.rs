mod errors;
mod packets;

extern crate tun;

use crate::errors::errors::RustTcpError;
use crate::packets::packets::on_request;

use std::env;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

const TUN_HEADER_SIZE: usize = 4;
const BUFF_MAX_SIZE: usize = 1504;

fn main() -> Result<(), RustTcpError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("[Usage]: {} [ipaddress]", args[0]);
    }

    let server_ipaddr: Ipv4Addr = args[1].parse().expect("Bad IPv4 address;");
    let mut config = tun::Configuration::default();
    config.address(server_ipaddr).netmask(24).up();

    let mut iface = tun::create(&config).expect("Failed to create device.");

    println!("Waiting packets on address : {server_ipaddr}");
    let mut request: Vec<u8> = vec![0u8; BUFF_MAX_SIZE];

    loop {
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

        let _ = on_request(
            &mut request[TUN_HEADER_SIZE..],
            &mut response,
            &server_ipaddr,
        );

        match iface.write(&response) {
            Ok(_) => (),
            Err(e) => eprintln!("Failed to send answer : {e}"),
        };
    }
}
