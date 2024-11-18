extern crate etherparse;

use crate::rusttcp::RustTcp;
use etherparse::err::packet::BuildWriteError;
use std::error::Error;
use std::fmt;
use std::sync::{MutexGuard, PoisonError};

#[derive(Debug)]
pub enum RustTcpError {
    PacketBuild(BuildWriteError),
    ThreadError,
    ConnectionNotFound(i32),
    ElementNotFound,
    BadPacketSize(usize),
    BadIpv4Address([u8; 4]),
    BadIPv4Proto(u8),
    BadIpv4Header,
    BadTcpHeader,
    BadTcpState,
    UnexpectedSeqNum,
    MaxRetransmissionsReached(u32),
}

impl fmt::Display for RustTcpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RustTcpError::PacketBuild(e) => write!(f, "Error: Can't build packet : {}", e),
            RustTcpError::ConnectionNotFound(fd) => {
                write!(
                    f,
                    "Error: Can't find connection with file descriptor : {}",
                    fd
                )
            }
            RustTcpError::ElementNotFound => write!(f, "Error: Can't find element"),
            RustTcpError::BadPacketSize(size) => write!(f, "Error: Bad Packet size : {}", size),
            RustTcpError::BadIPv4Proto(proto) => write!(f, "Error: Bad Ipv4 Protocol : {}", proto),
            RustTcpError::BadIpv4Address(addr) => {
                write!(f, "Error: Bad destination address : {:?}", addr)
            }
            RustTcpError::BadIpv4Header => {
                write!(f, "Error: Bad Ipv4 Header")
            }
            RustTcpError::BadTcpHeader => {
                write!(f, "Error: Bad Tcp Header")
            }
            RustTcpError::BadTcpState => {
                write!(f, "Error: Bad Tcp State")
            }
            RustTcpError::UnexpectedSeqNum => {
                write!(f, "Error: Unexpected Sequence Number")
            }
            RustTcpError::MaxRetransmissionsReached(value) => {
                write!(f, "Error: Max retransmissions reached : {}", value)
            }
            RustTcpError::ThreadError => {
                write!(f, "Error: Cannot acquire lock because of thread panic")
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
