package tcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/baxromumarov/tcp-ip-go/ip"
)

var tcpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 1500)
	},
}

const defaultWindowSize = 65535

type TCPFlag uint8

const (
	TCPFlagFIN TCPFlag = 1 << 0
	TCPFlagSYN TCPFlag = 1 << 1
	TCPFlagRST TCPFlag = 1 << 2
	TCPFlagPSH TCPFlag = 1 << 3
	TCPFlagACK TCPFlag = 1 << 4
	TCPFlagURG TCPFlag = 1 << 5
)

func (f TCPFlag) Has(flag TCPFlag) bool {
	return f&flag == flag
}

// Source Port (16 bits): The port number on the source host from which the packet was sent.
// Destination Port (16 bits): The port number on the destination host to which the packet is being sent.
// Sequence Number (32 bits): The sequence number of the first byte of data in this packet.
// Acknowledgment Number (32 bits): The next sequence number that the receiver expects to receive.
// Data Offset (4 bits): Indicates the size of the TCP header in 32-bit words.
// Window Size (16 bits): The size of the reception window, which indicates the amount of data that can be sent before an acknowledgment is required.
// Checksum (16 bits): Computed checksum of the entire packet (header and data).
// Urgent Pointer (16 bits): Points to the last byte of urgent data in the packet.

type TCP struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOff    uint8   // in 32-bit words (e.g. 5)
	Flags      TCPFlag // 6 bits
	Checksum   uint16
	WindowSize uint16
	UrgentPtr  uint16
	Payload    []byte
}

func ParseTCPHeader(data []byte) (*TCP, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short to be a TCP header")
	}

	dataOffset := data[12] >> 4
	if dataOffset < 5 {
		return nil, fmt.Errorf("invalid TCP data offset (header length): %d", dataOffset)
	}

	headerLen := int(dataOffset) * 4
	if len(data) < headerLen {
		return nil, fmt.Errorf("data shorter than TCP header length")
	}

	// TCP flags are 6 bits in lower bits of data[13]
	flags := TCPFlag(data[13] & 0x3F)

	return &TCP{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOff:    dataOffset,
		Flags:      flags,
		WindowSize: binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
		Payload:    data[headerLen:],
	}, nil
}

func (t *TCP) Marshal() []byte {
	if t == nil {
		return nil
	}

	var buf [20]byte
	binary.BigEndian.PutUint16(buf[0:2], t.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], t.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], t.Seq)
	binary.BigEndian.PutUint32(buf[8:12], t.Ack)
	buf[12] = t.DataOff << 4
	buf[13] = byte(t.Flags)
	binary.BigEndian.PutUint16(buf[14:16], t.WindowSize)
	binary.BigEndian.PutUint16(buf[16:18], t.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], t.UrgentPtr)

	return buf[:]
}

func (t *TCP) MarshalWithChecksum(srcIP, dstIP [16]byte) []byte {
	header := t.Marshal()
	pseudo := buildTCPPseudoHeader(srcIP, dstIP, uint16(len(header)+len(t.Payload)))

	buf := tcpBufferPool.Get().([]byte)

	buf = append(buf, pseudo...)
	buf = append(buf, header...)
	buf = append(buf, t.Payload...)

	if len(buf)%2 == 1 {
		buf = append(buf, 0)
	}

	t.Checksum = ip.ComputeChecksum(buf)
	binary.BigEndian.PutUint16(header[16:18], t.Checksum)

	result := append(header, t.Payload...)

	tcpBufferPool.Put(buf)

	return result
}

func buildTCPPseudoHeader(srcIP, dstIP [16]byte, tcpLength uint16) []byte {
	// if this is IPv4 (first 12 bytes are 0, last 4 contain the address)
	if srcIP[0] == 0 && srcIP[1] == 0 && srcIP[2] == 0 && srcIP[3] == 0 &&
		srcIP[4] == 0 && srcIP[5] == 0 && srcIP[6] == 0 && srcIP[7] == 0 &&
		srcIP[8] == 0 && srcIP[9] == 0 && srcIP[10] == 0xff && srcIP[11] == 0xff {
		// IPv4 pseudo-header (12 bytes)
		// For IPv4, extract the last 4 bytes from the [16]byte array
		// IPv4 addresses are stored in the last 4 bytes with 0xff, 0xff in bytes 10-11
		ph := make([]byte, 12)
		copy(ph[0:4], srcIP[12:16]) // Source IP (last 4 bytes)
		copy(ph[4:8], dstIP[12:16]) // Destination IP (last 4 bytes)
		ph[8] = 0                   // Zero
		ph[9] = 6                   // TCP protocol number
		binary.BigEndian.PutUint16(ph[10:12], tcpLength)
		return ph
	} else {
		// IPv6 pseudo-header (40 bytes)
		ph := make([]byte, 40)
		copy(ph[0:16], srcIP[:])  // Source IP (16 bytes)
		copy(ph[16:32], dstIP[:]) // Destination IP (16 bytes)
		binary.BigEndian.PutUint32(ph[32:36], uint32(tcpLength))
		ph[39] = 6 // TCP protocol number (last byte)
		return ph
	}
}

func calculateTCPChecksum(ipPacket *ip.IP, tcpHeader, payload []byte) uint16 {
	pseudoHeader := buildTCPPseudoHeader(ipPacket.SrcAddr, ipPacket.DestAddr, uint16(len(tcpHeader)+len(payload)))

	// Concatenate: pseudo + header + payload
	data := append(pseudoHeader, tcpHeader...)
	data = append(data, payload...)

	// Pad if odd length
	if len(data)%2 != 0 {
		data = append(data, 0)
	}

	return ip.ComputeChecksum(data)
}

// 4. TCP Packet Struct
// Combine Header + Payload:
// go
// Copy
// Edit
//Function to Marshal entire packet

type TCPPacket struct {
	Header  *TCP
	Payload []byte
}

func (t *TCPPacket) Marshal() []byte {
	return append(t.Header.Marshal(), t.Payload...)
}

// 5. Connection Functions
// These will be low-level raw implementations without OS TCP stack:
// DialTCP(dstIP string, dstPort uint16) (*TCPConn, error)
// ListenTCP(port uint16) (*TCPListener, error)
// AcceptTCP(listener *TCPListener) (*TCPConn, error)
type TCPState int

const (
	StateClosed TCPState = iota
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateTimeWait
)

type TCPConn struct {
	LocalIP     [16]byte
	RemoteIP    [16]byte
	LocalPort   uint16
	RemotePort  uint16
	State       TCPState
	Seq         uint32
	Ack         uint32
	RawSocketFD int
}

func DialTCP(dstIP string, dstPort uint16) (*TCPConn, error) {
	// 1. Parse destination IP
	dstAddr, version, err := ip.ParseIPAddress(dstIP)
	if err != nil {
		return nil, err
	}
	if version != ip.IPv4 {
		return nil, fmt.Errorf("unsupported IP version: %v", version)
	}

	// 2. Open raw socket
	fd, err := OpenRawSocket()
	if err != nil {
		return nil, fmt.Errorf("failed to open raw socket: %v", err)
	}

	// 3. Set local IP and port
	localIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}
	localPort := uint16(54321)

	// 4. Create TCP connection
	conn := &TCPConn{
		LocalIP:     localIP,
		RemoteIP:    dstAddr,
		LocalPort:   localPort,
		RemotePort:  dstPort,
		State:       StateClosed,
		RawSocketFD: fd,
	}

	// 5. Perform handshake
	if err := conn.handshake(); err != nil {
		defer func() { _ = conn.Close() }()
		return nil, fmt.Errorf("handshake failed: %v", err)
	}

	return conn, nil
}

type TCPListener struct {
	FD        int
	LocalIP   [16]byte
	LocalPort uint16
	mu        sync.Mutex
	conns     map[string]*TCPConn // remoteIP:remotePort
	acceptCh  chan *TCPConn
	closed    bool
}

func ListenTCP(addr string, port uint16) (*TCPListener, error) {
	localIP, _, err := ip.ParseIPAddress(addr)
	if err != nil {
		return nil, err
	}

	fd, err := OpenRawSocket()
	if err != nil {
		return nil, err
	}

	listener := &TCPListener{
		FD:        fd,
		LocalIP:   localIP,
		LocalPort: port,
		conns:     make(map[string]*TCPConn),
		acceptCh:  make(chan *TCPConn, 100),
	}

	// Start a goroutine to receive and handle incoming packets
	go listener.packetHandler()

	return listener, nil
}

func (l *TCPListener) packetHandler() {
	buf := make([]byte, 1500)

	for {
		if l.closed {
			return
		}

		n, _, err := syscall.Recvfrom(l.FD, buf, 0)
		if err != nil {
			continue
		}

		ipPacket, err := ip.ParseIPPacket(buf[:n])
		if err != nil || ipPacket.NextHeader != 6 {
			continue
		}

		tcpHdr, err := ParseTCPHeader(ipPacket.Payload)
		if err != nil {
			continue
		}

		if tcpHdr.DstPort != l.LocalPort {
			continue
		}

		remoteIP := ipPacket.SrcAddr
		key := connKey(remoteIP, tcpHdr.SrcPort)

		l.mu.Lock()
		conn, exists := l.conns[key]

		if tcpHdr.Flags&TCPFlagSYN != 0 && tcpHdr.Flags&TCPFlagACK == 0 {
			// Incoming SYN (new connection request)
			if exists {
				l.mu.Unlock()
				continue
			}

			conn = &TCPConn{
				LocalIP:     l.LocalIP,
				RemoteIP:    remoteIP,
				LocalPort:   l.LocalPort,
				RemotePort:  tcpHdr.SrcPort,
				Seq:         1000,
				Ack:         tcpHdr.Seq + 1,
				State:       StateSynReceived,
				RawSocketFD: l.FD,
			}
			l.conns[key] = conn

			l.mu.Unlock()
			err := l.sendSynAck(conn)
			if err != nil {
				l.mu.Lock()
				delete(l.conns, key)
				l.mu.Unlock()
			}
			continue
		}

		if exists && tcpHdr.Flags&TCPFlagACK != 0 && conn.State == StateSynReceived {
			if tcpHdr.Ack == conn.Seq+1 {
				conn.State = StateEstablished
				conn.Seq += 1
				conn.Ack = tcpHdr.Seq

				select {
				case l.acceptCh <- conn:
				default:
					log.Println("Accept channel full, dropping connection")
				}
			}
			l.mu.Unlock()
			continue
		}

		// Application data handling happens outside handshake block
		if exists && conn.State == StateEstablished {
			if tcpHdr.Flags&TCPFlagPSH != 0 || len(tcpHdr.Payload) > 0 {

				conn.Ack = tcpHdr.Seq + uint32(len(tcpHdr.Payload))

				// Send ACK for the received data
				ack := &TCP{
					SrcPort:    conn.LocalPort,
					DstPort:    conn.RemotePort,
					Seq:        conn.Seq,
					Ack:        conn.Ack,
					DataOff:    5,
					Flags:      TCPFlagACK,
					WindowSize: defaultWindowSize,
				}

				ackBytes := ack.MarshalWithChecksum(conn.LocalIP, conn.RemoteIP)

				ipPkt := &ip.IP{
					Version:    ip.IPv4,
					SrcAddr:    conn.LocalIP,
					DestAddr:   conn.RemoteIP,
					Payload:    ackBytes,
					NextHeader: 6,
					HopLimit:   64,
				}

				ipBytes, err := ipPkt.Marshal()
				if err == nil {
					sa := &syscall.SockaddrInet4{}
					copy(sa.Addr[:], conn.RemoteIP[12:16])
					syscall.Sendto(conn.RawSocketFD, ipBytes, 0, sa)
				}

				// Send response data back to client
				response := fmt.Sprintf("Server received: %s\n", string(tcpHdr.Payload))
				responseData := []byte(response)

				responseTCP := &TCP{
					SrcPort:    conn.LocalPort,
					DstPort:    conn.RemotePort,
					Seq:        conn.Seq,
					Ack:        conn.Ack,
					DataOff:    5,
					Flags:      TCPFlagPSH | TCPFlagACK,
					WindowSize: defaultWindowSize,
					Payload:    responseData,
				}

				responseBytes := responseTCP.MarshalWithChecksum(conn.LocalIP, conn.RemoteIP)

				responseIP := &ip.IP{
					Version:    ip.IPv4,
					SrcAddr:    conn.LocalIP,
					DestAddr:   conn.RemoteIP,
					Payload:    responseBytes,
					NextHeader: 6,
					HopLimit:   64,
				}

				responseIPBytes, err := responseIP.Marshal()
				if err == nil {
					responseSA := &syscall.SockaddrInet4{}
					copy(responseSA.Addr[:], conn.RemoteIP[12:16])
					syscall.Sendto(conn.RawSocketFD, responseIPBytes, 0, responseSA)
					conn.Seq += uint32(len(responseData))
				}
			}
		}

		l.mu.Unlock()
	}
}

func (l *TCPListener) sendSynAck(conn *TCPConn) error {
	synAck := &TCP{
		SrcPort:    conn.LocalPort,
		DstPort:    conn.RemotePort,
		Seq:        conn.Seq,
		Ack:        conn.Ack,
		DataOff:    5,
		Flags:      TCPFlagSYN | TCPFlagACK,
		WindowSize: defaultWindowSize,
	}

	tcpBytes := synAck.MarshalWithChecksum(conn.LocalIP, conn.RemoteIP)

	ipPacket := &ip.IP{
		Version:    ip.IPv4,
		SrcAddr:    conn.LocalIP,
		DestAddr:   conn.RemoteIP,
		Payload:    tcpBytes,
		NextHeader: 6,
		HopLimit:   64,
	}

	ipBytes, err := ipPacket.Marshal()
	if err != nil {
		return err
	}

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], conn.RemoteIP[12:16])

	return syscall.Sendto(l.FD, ipBytes, 0, sa)
}
func (l *TCPListener) Accept() (*TCPConn, error) {
	if l.closed {
		return nil, errors.New("listener closed")
	}
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-time.After(60 * time.Second):
		return nil, errors.New("accept timeout")
	}
}

func (l *TCPListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("already closed")
	}
	l.closed = true
	close(l.acceptCh)
	return syscall.Close(l.FD)
}

func connKey(ip [16]byte, port uint16) string {
	return net.IP(ip[12:16]).String() + ":" + strconv.Itoa(int(port))
}

//6. TCP State Machine
//Implement 3-way handshake:
//SYN → SYN-ACK → ACK
//Connection states:
//SYN_SENT
//SYN_RECEIVED
//ESTABLISHED
//Optional: FIN handling

//
//1. SYN: The initiating computer (or active client) sends a synchronize sequence number (SYN)
//packet to the receiving computer (usually a server). The SYN packet value is set to an arbitrary
//number (e.g., 100) to “ask” if any open connections are available.

//2. SYN-ACK: If the receiving computer (also known as a passive client) has open ports that
//can accept the connection, it sends back a synchronize-acknowledge (SYN-ACK) packet to the
//initiating computer. The packet includes two numbers: the receiving computer’s own SYN,
//which can be any arbitrary number as well (e.g., 200), and the ACK number, which is the
//initiating computer’s SYN plus one (e.g., 101).

// 3. ACK: The initiating computer (active client) then sends an acknowledgment sequence number (ACK)
// packet back to the receiving computer. This ACK packet is an acknowledgment of receipt of the
// SYN-ACK packet. The packet value is set to the receiving computer’s SYN (sent in step two)
// plus one again (e.g., 201). With this final step, the connection is established,
// and data transmission can begin.
func (conn *TCPConn) handshake() error {
	// 1. initialize
	conn.State = StateSynSent
	conn.Seq = rand.Uint32()
	// 2. send SYN
	syn := &TCP{
		SrcPort:    conn.LocalPort,
		DstPort:    conn.RemotePort,
		Seq:        conn.Seq,
		DataOff:    5,
		Flags:      TCPFlagSYN,
		WindowSize: defaultWindowSize,
	}

	synBytes := syn.MarshalWithChecksum(conn.LocalIP, conn.RemoteIP)

	ipPacket := &ip.IP{
		Version:    ip.IPv4,
		SrcAddr:    conn.LocalIP,
		DestAddr:   conn.RemoteIP,
		Payload:    synBytes,
		NextHeader: 6, // TCP
		HopLimit:   64,
	}

	ipBytes, err := ipPacket.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal IP packet: %v", err)
	}

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], conn.RemoteIP[12:16])

	if err := syscall.Sendto(conn.RawSocketFD, ipBytes, 0, sa); err != nil {
		return fmt.Errorf("send SYN failed: %v", err)
	}

	// 3. wait for SYN-ACK with timeout
	tv := syscall.Timeval{Sec: 5, Usec: 0}
	if err := syscall.SetsockoptTimeval(conn.RawSocketFD, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("failed to set recv timeout: %v", err)
	}

	buf := make([]byte, 1500)

	// Keep reading until we get a valid response from the server
	var tcp *TCP
	var remoteIP [4]byte

	for {
		n, from, err := syscall.Recvfrom(conn.RawSocketFD, buf, 0)
		if err != nil {
			return fmt.Errorf("recvfrom failed: %v", err)
		}

		fromAddr, ok := from.(*syscall.SockaddrInet4)
		if !ok {
			continue // Skip non-IPv4 packets
		}
		remoteIP = fromAddr.Addr
		if !bytes.Equal(remoteIP[:], conn.RemoteIP[12:16]) {
			continue // Skip packets from wrong IP
		}

		parsedIP, err := ip.ParseIPPacket(buf[:n])
		if err != nil {
			continue // Skip malformed IP packets
		}

		tcp, err = ParseTCPHeader(parsedIP.Payload)
		if err != nil {
			continue // Skip malformed TCP packets
		}

		// Check if this is a response from the server (not our own outgoing packet)
		if tcp.SrcPort != conn.RemotePort || tcp.DstPort != conn.LocalPort {
			continue // Skip packets not from server
		}

		// Handle the response from the server
		if tcp.Flags.Has(TCPFlagSYN) {
			// Server sent a SYN (either SYN-ACK or just SYN)

			// If it's a SYN-ACK, validate the acknowledgment
			if tcp.Flags.Has(TCPFlagACK) {
				if tcp.Ack != conn.Seq+1 {
					return fmt.Errorf("invalid SYN-ACK: flags=%#x ack=%d", tcp.Flags, tcp.Ack)
				}
			}
		} else {
			continue // Skip non-SYN packets
		}

		// We found a valid SYN-ACK response, break out of the loop
		break
	}

	// Set acknowledgment number to server's sequence number + 1
	conn.Ack = tcp.Seq + 1
	conn.Seq += 1 // our SYN used this seq
	conn.State = StateEstablished

	// 4. send ACK
	ack := &TCP{
		SrcPort:    conn.LocalPort,
		DstPort:    conn.RemotePort,
		Seq:        conn.Seq,
		Ack:        conn.Ack,
		DataOff:    5,
		Flags:      TCPFlagACK,
		WindowSize: defaultWindowSize,
	}

	ackBytes := ack.MarshalWithChecksum(conn.LocalIP, conn.RemoteIP)

	ackIP := &ip.IP{
		Version:    ip.IPv4,
		SrcAddr:    conn.LocalIP,
		DestAddr:   conn.RemoteIP,
		Payload:    ackBytes,
		NextHeader: 6,
		HopLimit:   64,
	}

	ipBytes, err = ackIP.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal ACK IP packet: %v", err)
	}

	if err := syscall.Sendto(conn.RawSocketFD, ipBytes, 0, sa); err != nil {
		return fmt.Errorf("send ACK failed: %v", err)
	}

	return nil
}

func (conn *TCPConn) Read(b []byte) (int, error) {
	buf := make([]byte, 1500)

	for {
		n, _, err := syscall.Recvfrom(conn.RawSocketFD, buf, 0)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}

			return 0, err
		}

		ipPacket, err := ip.ParseIPPacket(buf[:n])
		if err != nil {
			continue
		}

		tcpHdr, err := ParseTCPHeader(ipPacket.Payload)
		if err != nil {
			continue
		}

		if tcpHdr.SrcPort == conn.RemotePort && tcpHdr.DstPort == conn.LocalPort {
			if len(tcpHdr.Payload) > 0 {
				conn.Ack = tcpHdr.Seq + uint32(len(tcpHdr.Payload))
			}

			copyLen := len(tcpHdr.Payload)
			if copyLen > len(b) {
				copyLen = len(b)
			}
			copy(b, tcpHdr.Payload[:copyLen])

			return copyLen, nil
		}
	}
}

func (conn *TCPConn) Close() error {
	return syscall.Close(conn.RawSocketFD)
}

func OpenRawSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("failed to create raw socket: %v", err)
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("failed to set IP_HDRINCL: %v", err)
	}

	tv := syscall.Timeval{Sec: 5, Usec: 0}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("failed to set socket receive timeout: %v", err)
	}

	return fd, nil
}

func (conn *TCPConn) Write(b []byte) (int, error) {
	tcpSegment := &TCP{
		SrcPort:    conn.LocalPort,
		DstPort:    conn.RemotePort,
		Seq:        conn.Seq,
		Ack:        conn.Ack,
		DataOff:    5,
		Flags:      TCPFlagPSH | TCPFlagACK,
		WindowSize: 65535,
		Payload:    b,
	}

	tcpBytes := tcpSegment.MarshalWithChecksum(conn.LocalIP, conn.RemoteIP)

	ipPacket := &ip.IP{
		Version:    ip.IPv4,
		SrcAddr:    conn.LocalIP,
		DestAddr:   conn.RemoteIP,
		Payload:    tcpBytes,
		NextHeader: 6, // TCP
		HopLimit:   64,
	}

	ipBytes, err := ipPacket.Marshal()
	if err != nil {
		return 0, fmt.Errorf("failed to marshal IP packet: %v", err)
	}

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], conn.RemoteIP[12:16])

	err = syscall.Sendto(conn.RawSocketFD, ipBytes, 0, sa)
	if err != nil {
		return 0, fmt.Errorf("sendto failed: %v", err)
	}

	conn.Seq += uint32(len(b))

	return len(b), nil
}
