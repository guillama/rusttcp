extern crate etherparse;

use crate::rusttcp::{FileDescriptor, RustTcp};
use etherparse::err::packet::BuildWriteError;
use std::error::Error;
use std::fmt;
use std::sync::{MutexGuard, PoisonError};

#[derive(Debug)]
pub enum RustTcpError {
    /// Error while building a TCP packet.
    PacketBuild(BuildWriteError),

    /// A threading-related error occurred.
    ThreadError,

    /// Connection with the specified file descriptor was not found.
    ConnectionNotFound(FileDescriptor),

    /// An expected element was not found in the queue.
    ElementNotFound,

    /// Packet has an invalid or unexpected size.
    BadPacketSize(usize),

    /// Invalid IPv4 address encountered.
    BadIpv4Address([u8; 4]),

    /// Unsupported or invalid IPv4 protocol encountered.
    BadIPv4Proto(u8),

    /// Error in parsing or validating an IPv4 header.
    BadIpv4Header,

    /// Error in parsing or validating a TCP header.
    BadTcpHeader,

    /// Invalid or unexpected TCP state encountered.
    BadTcpState,

    /// Unexpected TCP sequence number encountered.
    UnexpectedSeqNum,

    /// Maximum retransmissions for a connection reached.
    MaxRetransmissionsReached(u32),
}

impl fmt::Display for RustTcpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RustTcpError::PacketBuild(e) => write!(f, "error while building a TCP packet : {}", e),
            RustTcpError::ConnectionNotFound(fd) => {
                write!(
                    f,
                    "connection with the specified file descriptor was not found : {:?}",
                    fd
                )
            }
            RustTcpError::ElementNotFound => {
                write!(f, "An expected element was not found in the queue")
            }
            RustTcpError::BadPacketSize(size) => {
                write!(f, "packet has an invalid or unexpected size : {}", size)
            }
            RustTcpError::BadIPv4Proto(proto) => write!(f, "bad Ipv4 Protocol : {}", proto),
            RustTcpError::BadIpv4Address(addr) => {
                write!(f, "invalid IPv4 address encountered : {:?}", addr)
            }
            RustTcpError::BadIpv4Header => {
                write!(f, "error in parsing or validating an IPv4 header")
            }
            RustTcpError::BadTcpHeader => {
                write!(f, "error in parsing or validating a TCP header")
            }
            RustTcpError::BadTcpState => {
                write!(f, "invalid or unexpected TCP state encountered")
            }
            RustTcpError::UnexpectedSeqNum => {
                write!(f, "unexpected TCP sequence number encountered")
            }
            RustTcpError::MaxRetransmissionsReached(value) => {
                write!(
                    f,
                    "maximum retransmissions for a connection reached : {}",
                    value
                )
            }
            RustTcpError::ThreadError => {
                write!(f, "a threading-related error occurred.")
            }
        }
    }
}

impl Error for RustTcpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RustTcpError::PacketBuild(e) => Some(e),
            _ => None,
        }
    }
}

impl From<BuildWriteError> for RustTcpError {
    fn from(value: BuildWriteError) -> Self {
        Self::PacketBuild(value)
    }
}

impl<'a> From<PoisonError<MutexGuard<'a, RustTcp>>> for RustTcpError {
    fn from(_value: PoisonError<MutexGuard<'a, RustTcp>>) -> Self {
        Self::ThreadError
    }
}
