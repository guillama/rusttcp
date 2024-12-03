# RustTCP

RustTCP is a minimalist implementation of the Transmission Control Protocol (TCP) in Rust, developed in compliance with [RFC 793](https://www.rfc-editor.org/rfc/rfc793).

## Getting Started

To run the server example in this repository, you need a working TUN driver on a Linux or macOS machine.

Creating the required TUN interface requires root privileges or, on Linux hosts only, the `CAP_NET_ADMIN` capability to be set in advance.
For more information about Linux capabilities, see the [capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html).

Run the server example using a TUN interface with an IPv4 address of `10.0.0.1`, the host's IPv4 address `10.0.0.2`, and a listening TCP port of `8888` by executing the following command:

```shell
cargo run --example server -- 10.0.0.1 10.0.0.2 8888
```

The command runs the RustTCP server and listen to port 8888 for an incoming TCP connection.
