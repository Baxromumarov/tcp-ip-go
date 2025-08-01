# Custom TCP/IP Implementation

A custom implementation of TCP/IP protocol stack using raw sockets in Go. This project demonstrates how to build a complete TCP/IP stack from scratch, including IP packet handling, TCP connection management, and reliable data transfer.

## Features

- **Raw Socket Implementation**: Direct interaction with the network layer using raw sockets
- **Custom IP Stack**: Complete IPv4 packet handling with checksum calculation
- **TCP Protocol**: Full TCP implementation including:
  - 3-way handshake (SYN → SYN-ACK → ACK)
  - Connection state management
  - Reliable data transfer with sequence numbers
  - Acknowledgment handling
  - Push and acknowledgment flags
- **Client-Server Communication**: Working client and server applications
- **Error Handling**: Robust error handling and packet validation

## Architecture

### Core Components

#### IP Layer (`ip/`)
- **`ip.go`**: IP packet structure and marshaling
- **`ip_parse.go`**: IP packet parsing and address handling
- **`ip_errors.go`**: Custom error types for IP operations

#### TCP Layer (`tcp/`)
- **`tcp.go`**: Complete TCP implementation including:
  - TCP header structure and flags
  - Connection management
  - Handshake implementation
  - Data transfer with sequence numbers
  - Raw socket integration

#### Applications
- **`client.go`**: TCP client application
- **`server.go`**: TCP server application

## How It Works

### TCP Handshake Process

1. **SYN**: Client sends synchronization packet with initial sequence number
2. **SYN-ACK**: Server responds with acknowledgment and its own sequence number
3. **ACK**: Client acknowledges server's sequence number to establish connection

### Data Transfer

1. **Client sends data** with PSH+ACK flags and payload
2. **Server receives data** and sends acknowledgment
3. **Server sends response** with PSH+ACK flags and response payload
4. **Client receives response** and acknowledges

### Raw Socket Integration

- Uses `syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)`
- Sets `IP_HDRINCL` flag for custom IP header construction
- Handles packet routing and filtering manually
- Implements custom checksum calculation

## Building and Running

### Prerequisites

- Go 1.16 or later
- Linux system (for raw socket support)
- Root/sudo privileges (required for raw sockets)

### Build

```bash
# Build client and server
go build -o client client.go
go build -o server server.go
```

### Run

```bash
# Terminal 1: Start server
sudo ./server

# Terminal 2: Run client
sudo ./client
```

### Using Makefile

```bash
# Build both applications
make build

# Run server
make run-server

# Run client
make run-client
```

## Usage Example

```bash
# Start server
$ sudo ./server
TCP server listening on port 8080

# Run client
$ sudo ./client
Connected to server at localhost:8080
Enter message to send (or 'exit' to quit): hello
Server response: Server received: hello

Enter message to send (or 'exit' to quit): test message
Server response: Server received: test message

Enter message to send (or 'exit' to quit): exit
```

## Technical Details

### TCP Header Structure

```go
type TCP struct {
    SrcPort    uint16
    DstPort    uint16
    Seq        uint32
    Ack        uint32
    DataOff    uint8
    Flags      TCPFlag
    Checksum   uint16
    WindowSize uint16
    UrgentPtr  uint16
    Payload    []byte
}
```

### TCP Flags

- `TCPFlagFIN`: Finish flag
- `TCPFlagSYN`: Synchronize flag
- `TCPFlagRST`: Reset flag
- `TCPFlagPSH`: Push flag
- `TCPFlagACK`: Acknowledgment flag
- `TCPFlagURG`: Urgent flag

### Connection States

- `StateClosed`: Connection is closed
- `StateSynSent`: SYN packet sent, waiting for SYN-ACK
- `StateSynReceived`: SYN received, connection established
- `StateEstablished`: Connection is active and ready for data transfer

### Packet Flow

1. **Client** creates raw socket and sends SYN packet
2. **Server** receives SYN, creates connection entry, sends SYN-ACK
3. **Client** receives SYN-ACK, sends ACK to complete handshake
4. **Data transfer** begins with PSH+ACK packets
5. **Server** processes data and sends response
6. **Client** receives response and continues communication

## Key Features

### Reliability
- Sequence number tracking for ordered delivery
- Acknowledgment mechanism for reliable transfer
- Checksum validation for data integrity

### Performance
- Buffer pooling for efficient memory usage
- Raw socket optimization for minimal overhead
- Efficient packet filtering and routing

### Robustness
- Error handling for malformed packets
- Timeout handling for lost packets
- Connection state validation

## Limitations

- **Platform**: Linux only (raw socket requirement)
- **Privileges**: Requires root/sudo access
- **Protocol**: IPv4 only
- **Features**: Basic TCP implementation (no window scaling, selective ACK, etc.)

## Educational Value

This implementation serves as an excellent learning resource for:

- **Network Protocols**: Understanding TCP/IP fundamentals
- **Raw Socket Programming**: Low-level network programming
- **Protocol Implementation**: Building reliable communication protocols
- **System Programming**: Working with kernel-level networking

## Contributing

Feel free to contribute improvements, bug fixes, or additional features:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Acknowledgments

- RFC 793 (TCP Specification)
- RFC 791 (IP Specification)
- Go standard library for networking primitives
- Linux kernel networking stack documentation 