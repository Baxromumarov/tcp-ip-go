package main

import (
	"fmt"
	"time"

	"github.com/baxromumarov/http-go/ip"
	"github.com/baxromumarov/http-go/tcp"
)

func main() {
	fmt.Println("🚀 Quick Performance Test")
	fmt.Println("==========================")

	// Test IP marshaling
	testIPMarshal()

	// Test TCP marshaling
	testTCPMarshal()

	// Test checksum calculation
	testChecksum()

	// Test IP parsing
	testIPParse()

	fmt.Println("\n✅ Performance test completed!")
}

func testIPMarshal() {
	fmt.Println("\n📦 IP Packet Marshaling:")

	srcAddr, _, _ := ip.ParseIPAddress("192.168.1.1")
	dstAddr, _, _ := ip.ParseIPAddress("192.168.1.2")

	ipPacket := &ip.IP{
		Version:    ip.IPv4,
		SrcAddr:    srcAddr,
		DestAddr:   dstAddr,
		Payload:    make([]byte, 1000),
		NextHeader: 6,
		HopLimit:   64,
	}

	iterations := 100000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		_, err := ipPacket.Marshal()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}

	duration := time.Since(start)
	opsPerSec := float64(iterations) / duration.Seconds()
	avgTime := duration.Nanoseconds() / int64(iterations)

	fmt.Printf("  Iterations: %d\n", iterations)
	fmt.Printf("  Total time: %v\n", duration)
	fmt.Printf("  Operations/sec: %.0f\n", opsPerSec)
	fmt.Printf("  Average time: %d ns/op\n", avgTime)
}

func testTCPMarshal() {
	fmt.Println("\n🔗 TCP Packet Marshaling:")

	srcAddr, _, _ := ip.ParseIPAddress("192.168.1.1")
	dstAddr, _, _ := ip.ParseIPAddress("192.168.1.2")

	tcpPacket := &tcp.TCP{
		SrcPort:    12345,
		DstPort:    80,
		Seq:        1000,
		Ack:        2000,
		DataOff:    5,
		Flags:      tcp.TCPFlagSYN,
		WindowSize: 65535,
		Payload:    make([]byte, 1000),
	}

	iterations := 10000 // Fewer iterations due to higher cost
	start := time.Now()

	for i := 0; i < iterations; i++ {
		tcpPacket.MarshalWithChecksum(srcAddr, dstAddr)
	}

	duration := time.Since(start)
	opsPerSec := float64(iterations) / duration.Seconds()
	avgTime := duration.Nanoseconds() / int64(iterations)

	fmt.Printf("  Iterations: %d\n", iterations)
	fmt.Printf("  Total time: %v\n", duration)
	fmt.Printf("  Operations/sec: %.0f\n", opsPerSec)
	fmt.Printf("  Average time: %d ns/op\n", avgTime)
}

func testChecksum() {
	fmt.Println("\n🔍 Checksum Calculation:")

	data := make([]byte, 1500)
	for i := range data {
		data[i] = byte(i % 256)
	}

	iterations := 100000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		ip.ComputeChecksum(data)
	}

	duration := time.Since(start)
	opsPerSec := float64(iterations) / duration.Seconds()
	avgTime := duration.Nanoseconds() / int64(iterations)

	fmt.Printf("  Iterations: %d\n", iterations)
	fmt.Printf("  Total time: %v\n", duration)
	fmt.Printf("  Operations/sec: %.0f\n", opsPerSec)
	fmt.Printf("  Average time: %d ns/op\n", avgTime)
}

func testIPParse() {
	fmt.Println("\n🌐 IP Address Parsing:")

	addresses := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.1.1.1",
	}

	iterations := 100000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		addr := addresses[i%len(addresses)]
		_, _, err := ip.ParseIPAddress(addr)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}

	duration := time.Since(start)
	opsPerSec := float64(iterations) / duration.Seconds()
	avgTime := duration.Nanoseconds() / int64(iterations)

	fmt.Printf("  Iterations: %d\n", iterations)
	fmt.Printf("  Total time: %v\n", duration)
	fmt.Printf("  Operations/sec: %.0f\n", opsPerSec)
	fmt.Printf("  Average time: %d ns/op\n", avgTime)
}
