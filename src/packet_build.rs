use etherparse::{PacketBuilder, TcpHeader};
use log::info;

use crate::{connection::Connection, errors::RustTcpError};

pub fn build_reset_packet(
    conn: Connection,
    tcphdr: &TcpHeader,
    payload_len: usize,
    packet: &mut [u8],
) -> Result<usize, RustTcpError> {
    let seqnum = match tcphdr.ack {
        true => tcphdr.acknowledgment_number,
        false => 0,
    };
    let acknum = tcphdr.sequence_number.wrapping_add(payload_len as u32);
    format_reset_packet(conn, seqnum, acknum, packet)
}

fn format_reset_packet(
    conn: Connection,
    seqnum: u32,
    acknum: u32,
    packet: &mut [u8],
) -> Result<usize, RustTcpError> {
    info!("Send RESET packet with seqnum {}", seqnum);

    let mut packet = &mut packet[..];
    PacketBuilder::ipv4(conn.dest_ip, conn.src_ip, 64)
        .tcp(conn.dest_port, conn.src_port, seqnum, 0)
        .rst()
        .ack(acknum)
        .write(&mut packet, &[])?;

    Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
}

pub fn build_syn_ack_packet(
    conn: Connection,
    seqnum: u32,
    acknum: u32,
    window_size: u16,
    packet: &mut [u8],
) -> Result<usize, RustTcpError> {
    let mut packet = &mut packet[..];
    PacketBuilder::ipv4(conn.dest_ip, conn.src_ip, 64)
        .tcp(conn.dest_port, conn.src_port, seqnum, window_size)
        .syn()
        .ack(acknum)
        .write(&mut packet, &[])?;

    Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
}

pub fn build_ack_packet(
    conn: Connection,
    data: &[u8],
    seqnum: u32,
    acknum: u32,
    window_size: u16,
    packet: &mut [u8],
) -> Result<usize, RustTcpError> {
    let mut packet = &mut packet[..];
    PacketBuilder::ipv4(conn.dest_ip, conn.src_ip, 64)
        .tcp(conn.dest_port, conn.src_port, seqnum, window_size)
        .ack(acknum)
        .write(&mut packet, data)?;

    Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN + data.len())
}

pub fn build_push_ack_packet(
    conn: Connection,
    data: &[u8],
    seqnum: u32,
    acknum: u32,
    window_size: u16,
    packet: &mut [u8],
) -> Result<usize, RustTcpError> {
    let mut packet = &mut packet[..];
    PacketBuilder::ipv4(conn.dest_ip, conn.src_ip, 64)
        .tcp(conn.dest_port, conn.src_port, seqnum, window_size)
        .ack(acknum)
        .psh()
        .write(&mut packet, data)?;

    Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN + data.len())
}

pub fn build_syn_packet(
    conn: Connection,
    seqnum: u32,
    window_size: u16,
    packet: &mut [u8],
) -> Result<usize, RustTcpError> {
    let mut packet = &mut packet[..];
    PacketBuilder::ipv4(conn.dest_ip, conn.src_ip, 64)
        .tcp(conn.dest_port, conn.src_port, seqnum, window_size)
        .syn()
        .write(&mut packet, &[])?;

    Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
}

pub fn build_fin_packet(
    conn: Connection,
    seqnum: u32,
    acknum: u32,
    packet: &mut [u8],
) -> Result<usize, RustTcpError> {
    let mut packet = &mut packet[..];
    PacketBuilder::ipv4(conn.dest_ip, conn.src_ip, 64)
        .tcp(conn.dest_port, conn.src_port, seqnum, 0)
        .ack(acknum)
        .fin()
        .write(&mut packet, &[])?;

    Ok(etherparse::Ipv4Header::MIN_LEN + etherparse::TcpHeader::MIN_LEN)
}
