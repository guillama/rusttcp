extern crate tun;

use std::env;
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("[Usage]: {} [ipaddress]", args[0]);
    }

    let ipaddr: &String = &args[1];
    let mut config = tun::Configuration::default();
    config.address(ipaddr).netmask(24).up();

    let mut iface = tun::create(&config).unwrap();
    println!("Waiting packets on address : {ipaddr}");

    loop {
        read_packets(&mut iface)?;
    }
}

fn read_packets<T: Read>(iface: &mut T) -> io::Result<()> {
    let mut buf = [0; 1504];
    let bytes_read = iface.read(&mut buf)?;

    let flags = u16::from_be_bytes([buf[0], buf[1]]);
    let proto = u16::from_be_bytes([buf[2], buf[3]]);
    println!("flags: {flags} proto: {proto}");

    // Skip the first 4 bytes (irrelevant data)
    // Note: MacOS includes an unknown TUN header..
    println!("Read {} bytes : {:x?}", bytes_read, &buf[4..bytes_read]);

    Ok(())
}
