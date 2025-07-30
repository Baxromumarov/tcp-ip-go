package ip

import (
	"encoding/binary"
	"testing"
)

func TestParseIPAddress_IPv4(t *testing.T) {
	addr, version, err := ParseIPAddress("192.168.1.1")
	if err != nil {
		t.Fatalf("Failed to parse IPv4 address: %v", err)
	}

	if version != IPv4 {
		t.Errorf("Expected IPv4, got %v", version)
	}

	// Check that IPv4 is stored in the last 4 bytes with 0xff, 0xff in bytes 10-11
	if addr[10] != 0xff || addr[11] != 0xff {
		t.Errorf("Expected 0xff, 0xff in bytes 10-11, got %02x, %02x", addr[10], addr[11])
	}

	// Check the actual IP address
	if addr[12] != 192 || addr[13] != 168 || addr[14] != 1 || addr[15] != 1 {
		t.Errorf("Expected 192.168.1.1, got %d.%d.%d.%d", addr[12], addr[13], addr[14], addr[15])
	}
}

func TestParseIPAddress_IPv6(t *testing.T) {
	addr, version, err := ParseIPAddress("2001:db8::1")
	if err != nil {
		t.Fatalf("Failed to parse IPv6 address: %v", err)
	}

	if version != IPv6 {
		t.Errorf("Expected IPv6, got %v", version)
	}

	// Check that it's not an IPv4-mapped address
	if addr[10] == 0xff && addr[11] == 0xff {
		t.Error("IPv6 address should not have 0xff, 0xff in bytes 10-11")
	}
}

func TestIPMarshal_IPv4(t *testing.T) {
	srcAddr, _, _ := ParseIPAddress("192.168.1.1")
	dstAddr, _, _ := ParseIPAddress("192.168.1.2")

	ip := &IP{
		Version:    IPv4,
		SrcAddr:    srcAddr,
		DestAddr:   dstAddr,
		Payload:    []byte{1, 2, 3, 4},
		NextHeader: 6, // TCP
		HopLimit:   64,
	}

	data, err := ip.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal IPv4: %v", err)
	}

	// Check minimum length (20 bytes header + 4 bytes payload)
	if len(data) < 24 {
		t.Errorf("Expected at least 24 bytes, got %d", len(data))
	}

	// Check version (should be 4)
	version := data[0] >> 4
	if version != 4 {
		t.Errorf("Expected version 4, got %d", version)
	}

	// Check header length (should be 5 for 20 bytes)
	headerLen := data[0] & 0x0F
	if headerLen != 5 {
		t.Errorf("Expected header length 5, got %d", headerLen)
	}

	// Check total length
	totalLen := binary.BigEndian.Uint16(data[2:4])
	if totalLen != 24 {
		t.Errorf("Expected total length 24, got %d", totalLen)
	}

	// Check protocol (should be 6 for TCP)
	if data[9] != 6 {
		t.Errorf("Expected protocol 6, got %d", data[9])
	}

	// Check TTL
	if data[8] != 64 {
		t.Errorf("Expected TTL 64, got %d", data[8])
	}
}

func TestIPString_IPv4(t *testing.T) {
	srcAddr, _, _ := ParseIPAddress("192.168.1.1")
	dstAddr, _, _ := ParseIPAddress("192.168.1.2")

	ip := &IP{
		Version:  IPv4,
		SrcAddr:  srcAddr,
		DestAddr: dstAddr,
	}

	str := ip.String()
	expected := "192.168.1.1 -> 192.168.1.2"
	if str != expected {
		t.Errorf("Expected %s, got %s", expected, str)
	}
}

func TestComputeChecksum(t *testing.T) {
	// Test with simple data
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	checksum := ComputeChecksum(data)

	// Checksum should not be 0 (unless data is all zeros)
	if checksum == 0 {
		t.Error("Checksum should not be 0 for non-zero data")
	}

	// Test with odd length data
	oddData := []byte{0x00, 0x01, 0x02}
	oddChecksum := ComputeChecksum(oddData)
	if oddChecksum == 0 {
		t.Error("Checksum should not be 0 for odd length data")
	}
}

func TestParseIPPacket_IPv4(t *testing.T) {
	// Create a simple IPv4 packet
	srcAddr, _, _ := ParseIPAddress("192.168.1.1")
	dstAddr, _, _ := ParseIPAddress("192.168.1.2")

	ip := &IP{
		Version:    IPv4,
		SrcAddr:    srcAddr,
		DestAddr:   dstAddr,
		Payload:    []byte{1, 2, 3, 4},
		NextHeader: 6,
		HopLimit:   64,
	}

	data, err := ip.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Parse it back
	parsed, err := ParseIPPacket(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	// Check that it matches
	if parsed.Version != ip.Version {
		t.Errorf("Version mismatch: expected %v, got %v", ip.Version, parsed.Version)
	}

	if parsed.NextHeader != ip.NextHeader {
		t.Errorf("Protocol mismatch: expected %d, got %d", ip.NextHeader, parsed.NextHeader)
	}

	if len(parsed.Payload) != len(ip.Payload) {
		t.Errorf("Payload length mismatch: expected %d, got %d", len(ip.Payload), len(parsed.Payload))
	}
}
