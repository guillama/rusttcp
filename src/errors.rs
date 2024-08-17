pub mod errors {
    use std::error;
    use std::fmt;

    #[derive(Debug)]
    pub enum RustTcpError {
        BadPacketSize(usize),
        BadAddress([u8; 4]),
        BadProto(u8),
        BadIpv4Header,
        BadTcpHeader,
    }

    impl fmt::Display for RustTcpError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
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
            }
        }
    }

    impl error::Error for RustTcpError {
        fn source(&self) -> Option<&(dyn error::Error + 'static)> {
            match *self {
                RustTcpError::BadPacketSize(_) => None,
                RustTcpError::BadProto(_) => None,
                RustTcpError::BadAddress(_) => None,
                RustTcpError::BadIpv4Header => None,
                RustTcpError::BadTcpHeader => None,
            }
        }
    }
}
