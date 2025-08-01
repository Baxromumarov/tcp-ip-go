package tcp

import (
	"encoding/binary"
	"testing"

	"github.com/baxromumarov/tcp-ip-go/ip"
)

func TestCalculateTCPChecksum_CustomPorts(t *testing.T) {
	srcIP, _, _ := ip.ParseIPAddress("192.168.0.1")
	dstIP, _, _ := ip.ParseIPAddress("192.168.0.2")

	ipHeader := ip.IP{
		Version:  ip.IPv4,
		SrcAddr:  srcIP,
		DestAddr: dstIP,
	}

	tcpHeader := TCP{
		SrcPort:    80,
		DstPort:    8080,
		Seq:        0,
		Ack:        0,
		DataOff:    5,
		Flags:      0x02, // SYN flag
		WindowSize: 65535,
	}

	var payload []byte // empty payload

	// Calculate expected checksum manually for verification
	expectedChecksum := calculateExpectedChecksum(&ipHeader, tcpHeader.Marshal(), payload)

	checksum := calculateTCPChecksum(&ipHeader, tcpHeader.Marshal(), payload)

	if checksum != expectedChecksum {
		t.Errorf("Checksum mismatch: got 0x%X want 0x%X", checksum, expectedChecksum)
		t.Logf("TCP Header: %+v", tcpHeader)
		t.Logf("IP Header: %+v", ipHeader)
	}
}

// calculateExpectedChecksum calculates the expected TCP checksum manually
func calculateExpectedChecksum(ipHeader *ip.IP, tcpHeader, payload []byte) uint16 {
	// Build pseudo-header
	pseudoHeader := buildTCPPseudoHeader(ipHeader.SrcAddr, ipHeader.DestAddr, uint16(len(tcpHeader)+len(payload)))

	// Concatenate: pseudo + header + payload
	data := append(pseudoHeader, tcpHeader...)
	data = append(data, payload...)

	// Pad if odd length
	if len(data)%2 != 0 {
		data = append(data, 0)
	}

	// Calculate checksum
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}

	// Handle carry
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}

func TestBuildPseudoHeader(t *testing.T) {
	srcIP, _, _ := ip.ParseIPAddress("192.168.0.1")
	dstIP, _, _ := ip.ParseIPAddress("192.168.0.2")

	ipHeader := ip.IP{
		Version:  ip.IPv4,
		SrcAddr:  srcIP,
		DestAddr: dstIP,
	}

	pseudo := buildTCPPseudoHeader(ipHeader.SrcAddr, ipHeader.DestAddr, 20)

	// IPv4 pseudo-header should be 12 bytes
	if len(pseudo) != 12 {
		t.Errorf("Expected 12 bytes, got %d", len(pseudo))
	}

	// Check source IP (should be 192.168.0.1)
	if pseudo[0] != 192 || pseudo[1] != 168 || pseudo[2] != 0 || pseudo[3] != 1 {
		t.Errorf("Source IP mismatch: got %d.%d.%d.%d, want 192.168.0.1",
			pseudo[0], pseudo[1], pseudo[2], pseudo[3])
	}

	// Check destination IP (should be 192.168.0.2)
	if pseudo[4] != 192 || pseudo[5] != 168 || pseudo[6] != 0 || pseudo[7] != 2 {
		t.Errorf("Destination IP mismatch: got %d.%d.%d.%d, want 192.168.0.2",
			pseudo[4], pseudo[5], pseudo[6], pseudo[7])
	}

	// Check protocol (should be 6 for TCP)
	if pseudo[9] != 6 {
		t.Errorf("Protocol mismatch: got %d, want 6", pseudo[9])
	}

	// Check length (should be 20)
	length := binary.BigEndian.Uint16(pseudo[10:12])
	if length != 20 {
		t.Errorf("Length mismatch: got %d, want 20", length)
	}
}

func TestTCPConnHandshake(t *testing.T) {
	// This test verifies that the handshake function is properly integrated
	// Note: This would require a mock server or network setup for full testing

	// Test that the handshake function exists and can be called
	conn := &TCPConn{
		LocalIP:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 100},
		RemoteIP:    [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
		LocalPort:   54321,
		RemotePort:  80,
		State:       StateClosed,
		RawSocketFD: -1, // Invalid FD for testing
	}

	// This should fail because we don't have a valid socket
	err := conn.handshake()
	if err == nil {
		t.Error("Expected handshake to fail with invalid socket")
	}

	// Verify the function exists and is callable (this is a compile-time check)
	_ = conn.handshake // This will fail at compile time if the function doesn't exist
}
