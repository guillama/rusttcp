use std::fmt;

#[derive(Debug)]
pub enum RustTcpError {
    Internal,
    BadPacketSize(usize),
    BadAddress([u8; 4]),
    BadProto(u8),
    BadIpv4Header,
    BadTcpHeader,
    BadState,
}

impl fmt::Display for RustTcpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RustTcpError::Internal => write!(f, "Internal error"),
            RustTcpError::BadPacketSize(size) => write!(f, "Bad Packet size : {}", size),
            RustTcpError::BadProto(proto) => write!(f, "Error: Bad Ipv4 Protocol : {}", proto),
            RustTcpError::BadAddress(addr) => {
                write!(f, "Error: Bad destination address : {:?}", addr)
            }
            RustTcpError::BadIpv4Header => {
                write!(f, "Error: Bad Ipv4 Header")
            }
            RustTcpError::BadTcpHeader => {
                write!(f, "Error: Bad Tcp Header")
            }
            RustTcpError::BadState => {
                write!(f, "Error: Bad Tcp State")
            }
        }
    }
}
