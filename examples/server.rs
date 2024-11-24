//! # RustTCP with TUN Interface
//!
//! This program implements a TCP stack using the RustTCP library, integrating it with a TUN interface.
//! It provides a simple, event-driven TCP implementation for handling connections and data transfer
//! between a host and a network interface.

extern crate tun;

use core::str;
use env_logger::Builder;
use log::{debug, error, info, LevelFilter};
use rusttcp::errors::RustTcpError;
use rusttcp::rusttcp::{RustTcp, RustTcpBuilder, RustTcpMode, TcpEvent};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{thread, time};
use tun::Device;

const MAX_BUF_SIZE: usize = 8 * 1024;
const DEFAULT_PORT: u16 = 8888;
const HOST_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 255);
const DEFAULT_THREAD_SLEEP_MS: u64 = 10;
const MAX_PROGRAM_ARGS: usize = 3;
const TUN_HEADER_SIZE: usize = 4;

type RustTcpGuard = Arc<Mutex<RustTcp>>;
type IfaceDevice = tun::platform::macos::Device;

fn log_init() {
    Builder::new()
        .filter_level(LevelFilter::Info)
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

fn main() {
    log_init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < MAX_PROGRAM_ARGS {
        panic!("[Usage]: {} [ipaddress]", args[0]);
    }

    let host_ipaddr: Ipv4Addr = args[1].parse().expect("Error: Bad Ipv4 String");
    let iface_ipaddr: Ipv4Addr = args[2].parse().expect("Error: Bad Ipv4 String");

    info!(
        "Rust TCP with host address {} and interface address {}",
        host_ipaddr, iface_ipaddr
    );

    let tcp_guard = Arc::new(Mutex::new(
        RustTcpBuilder::new(host_ipaddr.octets()).build(),
    ));
    let mut tcp_thread = Arc::clone(&tcp_guard);
    thread::spawn(move || read(&mut tcp_thread, iface_ipaddr, host_ipaddr));

    run(&tcp_guard).expect("Main thread failed");
}

fn run(tcp_guard: &RustTcpGuard) -> Result<(), RustTcpError> {
    let mut fd = tcp_guard.lock()?.open(RustTcpMode::Passive(DEFAULT_PORT))?;

    loop {
        {
            let mut tcp = tcp_guard.lock()?;
            match tcp.poll() {
                TcpEvent::DataReceived(_) => {
                    debug!("TcpEvent: DataReceived");

                    let mut buf = [0; MAX_BUF_SIZE];
                    if let Ok(n) = tcp.read(fd, &mut buf) {
                        info!("read {} bytes : {}", n, str::from_utf8(&buf).unwrap());
                    }
                }
                TcpEvent::ConnectionClosing => {
                    debug!("TcpEvent: ConnectionClosing");
                    tcp.close(fd)
                }
                TcpEvent::ConnectionClosed => {
                    debug!("TcpEvent: ConnectionClosed");
                    fd = tcp.open(RustTcpMode::Passive(DEFAULT_PORT))?
                }
                _ => (),
            }
        }

        thread::sleep(time::Duration::from_millis(DEFAULT_THREAD_SLEEP_MS));
    }
}

fn read(tcp: &mut RustTcpGuard, iface_ip: Ipv4Addr, host_ip: Ipv4Addr) -> Result<(), RustTcpError> {
    let mut config = tun::Configuration::default();
    config
        .address(iface_ip)
        .destination(host_ip)
        .netmask(HOST_NETMASK)
        .up();

    info!("Start READ thread");

    let iface: IfaceDevice = match tun::create(&config) {
        Ok(iface) => {
            info!("Interface created successfully: {:?}", iface.name());
            iface
        }
        Err(e) => {
            error!("Failed to create device: {:?}", e);
            return Err(RustTcpError::BadTcpHeader);
        }
    };

    iface.set_nonblock().unwrap();

    run_read(tcp, iface)
}

fn run_read(tcp: &mut RustTcpGuard, mut iface: IfaceDevice) -> Result<(), RustTcpError> {
    let mut packet = [0; MAX_BUF_SIZE];

    loop {
        if let Ok(n) = tcp.lock()?.on_user_event(&mut packet[TUN_HEADER_SIZE..]) {
            if let Err(e) = iface.write(&mut packet[..TUN_HEADER_SIZE + n]) {
                error!("Error: write failed : {:?}", e);
            }
        }

        if let Ok(n) = tcp.lock()?.on_timer_event(&mut packet[TUN_HEADER_SIZE..]) {
            if let Err(e) = iface.write(&mut packet[..TUN_HEADER_SIZE + n]) {
                error!("Error: write failed : {:?}", e);
            }
        }

        if let Ok(n) = iface.read(&mut packet) {
            if n < TUN_HEADER_SIZE {
                continue;
            }

            on_packet(tcp, &mut iface, &packet[..n])?;
        }
    }
}

fn on_packet(
    tcp: &RustTcpGuard,
    iface: &mut IfaceDevice,
    packet: &[u8],
) -> Result<(), RustTcpError> {
    let mut buf = [0; MAX_BUF_SIZE];
    buf[..TUN_HEADER_SIZE].clone_from_slice(&packet[..TUN_HEADER_SIZE]);

    match tcp
        .lock()?
        .on_packet(&packet[TUN_HEADER_SIZE..], &mut buf[TUN_HEADER_SIZE..])
    {
        Ok(n) if n > 0 => {
            if let Err(e) = iface.write(&mut buf[..TUN_HEADER_SIZE + n]) {
                error!("Error: write failed : {:?}", e);
            }
        }
        Err(e) => error!("Error: on_packet failed : {:?}", e),
        _ => (),
    };

    Ok(())
}
