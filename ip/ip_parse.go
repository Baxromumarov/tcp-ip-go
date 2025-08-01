package ip

import (
	"encoding/binary"
	"errors"
	"net"
)

// Parses both IPv4 and IPv6 packets based on version
func ParseIPPacket(data []byte) (*IP, error) {
	if len(data) < 1 {
		return nil, errors.New("empty packet")
	}

	version := IPVersion(data[0] >> 4)
	switch version {
	case IPv4:
		return ParseIPv4Packet(data)
	case IPv6:
		return ParseIPv6Packet(data)
	default:
		return nil, errors.New("unknown IP version")
	}
}

func ParseIPv4Packet(data []byte) (*IP, error) {
	if len(data) < IPv4len {
		return nil, errors.New("IPv4 packet too short")
	}

	var src, dst [16]byte
	src[10], src[11] = 0xff, 0xff
	dst[10], dst[11] = 0xff, 0xff
	copy(src[12:], data[12:16])
	copy(dst[12:], data[16:20])

	headerLen := int(data[0]&0x0F) * 4
	if len(data) < headerLen {
		return nil, errors.New("invalid IPv4 header length")
	}

	return &IP{
		Version:      IPv4,
		SrcAddr:      src,
		DestAddr:     dst,
		TrafficClass: data[1],
		Payload:      data[headerLen:],
		Header:       data[:headerLen],
		NextHeader:   data[9],
		HopLimit:     data[8],
	}, nil
}

func ParseIPv6Packet(data []byte) (*IP, error) {
	if len(data) < IPv6len {
		return nil, errors.New("IPv6 packet too short")
	}

	trafficClass := ((data[0] & 0x0F) << 4) | (data[1] >> 4)
	flowLabel := uint32(data[1]&0x0F)<<16 | uint32(data[2])<<8 | uint32(data[3])
	payloadLen := binary.BigEndian.Uint16(data[4:6])
	if int(IPv6len+payloadLen) > len(data) {
		return nil, errors.New("IPv6 payload length mismatch")
	}

	var src, dst [16]byte
	copy(src[:], data[8:24])
	copy(dst[:], data[24:40])

	return &IP{
		Version:      IPv6,
		SrcAddr:      src,
		DestAddr:     dst,
		TrafficClass: trafficClass,
		FlowLabel:    flowLabel,
		Payload:      data[40 : 40+payloadLen],
		Header:       data[:40],
		NextHeader:   data[6],
		HopLimit:     data[7],
	}, nil
}

// ParseIPAddress converts string to [16]byte and detects IP version
func ParseIPAddress(addr string) ([16]byte, IPVersion, error) {
	var ipArray [16]byte

	ip := net.ParseIP(addr)

	if ip == nil {
		return ipArray, 0, errors.New("invalid IP address")
	}
	if ip4 := ip.To4(); ip4 != nil {
		ipArray[10], ipArray[11] = 0xff, 0xff
		copy(ipArray[12:], ip4)
		return ipArray, IPv4, nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		copy(ipArray[:], ip16)
		return ipArray, IPv6, nil
	}
	return ipArray, 0, errors.New("failed to parse IP")
}
