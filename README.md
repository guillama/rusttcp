# RustTCP

RustTCP is a minimalistic implementation of the Transmission Control Protocol (TCP) in Rust, built in compliance with RFC 793.
Originally conceived as an educational project, RustTCP emphasizes simplicity, clarity, and adherence to robust development practices.

Designed with extensibility in mind, RustTCP features a modular architecture supported by a comprehensive suite of unit tests.
This ensures reliability while enabling developers to easily extend and adapt the library to their specific needs.

## Features

### Event-Driven Architecture

RustTCP utilizes an event-based design to process TCP actions like opening connections, receiving data, and handling timeouts.

### Buffer Management

Efficient handling of send and receive buffers ensures smooth data transfer, minimizing unnecessary memory allocations and copies.

### Timeout and Retransmission

Manages retransmissions using an exponential backoff strategy for unacknowledged packets. Timeouts are tracked and handled with precision to ensure reliable delivery.

### Connection Tracking

RustTCP supports multiple concurrent connections, managing them through a mapping of Connection objects and tracking states, sequence numbers, and buffers independently for each connection.
