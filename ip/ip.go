// Package http_go according to https://datatracker.ietf.org/doc/html/rfc791
package ip

import (
	"encoding/binary"
	"fmt"
)

type IPVersion int

const (
	IPv4 IPVersion = 4
	IPv6 IPVersion = 6
)

// IP address lengths (bytes).
const (
	IPv4len = 4
	IPv6len = 16
)

type IP struct {
	Version      IPVersion
	SrcAddr      [16]byte // useful 16 bytes to cover IPv6; IPv4 will only use first 4
	DestAddr     [16]byte
	TrafficClass uint8
	FlowLabel    uint32
	Payload      []byte
	Header       []byte
	NextHeader   uint8 // e.g., TCP = 6
	HopLimit     uint8
}

func (ip *IP) Marshal() ([]byte, error) {
	switch ip.Version {
	case IPv4:
		return ip.marshalIPv4()
	case IPv6:
		return ip.marshalIPv6()
	default:
		return nil, fmt.Errorf("%s: %d", ErrInvalidIP, ip.Version)

	}

}

func (ip *IP) marshalIPv4() ([]byte, error) {
	headerLen := 20
	totalLen := uint16(headerLen + len(ip.Payload))
	buf := make([]byte, totalLen)

	// Version (4 bits) + The Internet Header Length (IHL) (4 bits)
	buf[0] = byte((4 << 4) | (headerLen / 4))

	// Differentiated Services Code Point (DSCP) (6 bits) + Explicit Congestion Notification (ECN) (2 bits)
	buf[1] = 0

	// Total Length (16 bits)
	binary.BigEndian.PutUint16(buf[2:4], totalLen)

	// Identification (16 bits)
	binary.BigEndian.PutUint16(buf[4:6], 0x0000)

	// Flags (3 bits) + Fragment Offset (13 bits)
	binary.BigEndian.PutUint16(buf[6:8], 0x4000)

	// Time to Live (8 bits)
	buf[8] = ip.HopLimit

	// Protocol (8 bits) (TCP = 6)
	buf[9] = ip.NextHeader

	// Header Checksum (initially 0)
	copy(buf[12:16], ip.SrcAddr[12:16])
	copy(buf[16:20], ip.DestAddr[12:16])

	// Compute checksum
	checksum := ComputeChecksum(buf[:headerLen])
	binary.BigEndian.PutUint16(buf[10:12], checksum)

	// Append payload
	copy(buf[headerLen:], ip.Payload)

	return buf, nil
}

func ComputeChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		} else {
			// Handle odd-length data by padding with zero
			sum += uint32(data[i]) << 8
		}
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (ip *IP) marshalIPv6() ([]byte, error) {
	const headerLen = 40
	buf := make([]byte, headerLen+len(ip.Payload))

	// Version (4 bits), Traffic Class (8), Flow Label (20)
	verTCFL := (uint32(6) << 28) | (uint32(ip.TrafficClass) << 20) | (ip.FlowLabel & 0xFFFFF)
	binary.BigEndian.PutUint32(buf[0:4], verTCFL)

	// Payload Length (16 bits)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(ip.Payload)))

	// Next Header (8 bits)
	buf[6] = ip.NextHeader

	// Hop Limit (8 bits)
	buf[7] = ip.HopLimit

	// Source Address (128 bits / 16 bytes)
	copy(buf[8:24], ip.SrcAddr[:])

	// Destination Address (128 bits / 16 bytes)
	copy(buf[24:40], ip.DestAddr[:])

	// Payload
	copy(buf[headerLen:], ip.Payload)

	return buf, nil
}

func (ip *IP) String() string {
	var srcStr, dstStr string

	//  IPv4 (stored in last 4 bytes with 0xff, 0xff in bytes 10-11)
	if ip.SrcAddr[10] == 0xff && ip.SrcAddr[11] == 0xff {
		srcStr = fmt.Sprintf("%d.%d.%d.%d", ip.SrcAddr[12], ip.SrcAddr[13], ip.SrcAddr[14], ip.SrcAddr[15])
		dstStr = fmt.Sprintf("%d.%d.%d.%d", ip.DestAddr[12], ip.DestAddr[13], ip.DestAddr[14], ip.DestAddr[15])
	} else {
		// IPv6 - format as hex groups
		srcStr = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			ip.SrcAddr[0], ip.SrcAddr[1], ip.SrcAddr[2], ip.SrcAddr[3],
			ip.SrcAddr[4], ip.SrcAddr[5], ip.SrcAddr[6], ip.SrcAddr[7],
			ip.SrcAddr[8], ip.SrcAddr[9], ip.SrcAddr[10], ip.SrcAddr[11],
			ip.SrcAddr[12], ip.SrcAddr[13], ip.SrcAddr[14], ip.SrcAddr[15])
		dstStr = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			ip.DestAddr[0], ip.DestAddr[1], ip.DestAddr[2], ip.DestAddr[3],
			ip.DestAddr[4], ip.DestAddr[5], ip.DestAddr[6], ip.DestAddr[7],
			ip.DestAddr[8], ip.DestAddr[9], ip.DestAddr[10], ip.DestAddr[11],
			ip.DestAddr[12], ip.DestAddr[13], ip.DestAddr[14], ip.DestAddr[15])
	}

	return fmt.Sprintf("%s -> %s", srcStr, dstStr)
}
