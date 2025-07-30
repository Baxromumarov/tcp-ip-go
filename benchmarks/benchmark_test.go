package benchmarks

import (
	"net"
	"testing"
	"time"

	"github.com/baxromumarov/http-go/ip"
	"github.com/baxromumarov/http-go/tcp"
)

// Benchmark IP packet marshaling
func BenchmarkIPMarshal_Custom(b *testing.B) {
	srcAddr, _, _ := ip.ParseIPAddress("192.168.1.1")
	dstAddr, _, _ := ip.ParseIPAddress("192.168.1.2")

	ipPacket := &ip.IP{
		Version:    ip.IPv4,
		SrcAddr:    srcAddr,
		DestAddr:   dstAddr,
		Payload:    make([]byte, 1000), // 1KB payload
		NextHeader: 6,                  // TCP
		HopLimit:   64,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ipPacket.Marshal()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark TCP packet marshaling
func BenchmarkTCPMarshal_Custom(b *testing.B) {
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
		Payload:    make([]byte, 1000), // 1KB payload
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tcpPacket.MarshalWithChecksum(srcAddr, dstAddr)
	}
}

// Benchmark checksum calculation
func BenchmarkChecksum_Custom(b *testing.B) {
	data := make([]byte, 1500) // Typical MTU size
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip.ComputeChecksum(data)
	}
}

// Benchmark IP address parsing
func BenchmarkIPParse_Custom(b *testing.B) {
	addresses := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.1.1.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := addresses[i%len(addresses)]
		_, _, err := ip.ParseIPAddress(addr)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark std library TCP connection (for comparison)
func BenchmarkTCPConnection_StdLib(b *testing.B) {
	// Start a simple TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Simple echo server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			conn.Write(buf[:n])
		}
	}()

	// Wait for server to be ready
	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			b.Fatal(err)
		}

		// Send and receive data
		conn.Write([]byte("hello"))
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Close()
	}
}

// Benchmark custom TCP connection (when implemented)
func BenchmarkTCPConnection_Custom(b *testing.B) {
	// This will be implemented once you have a working TCP server
	// For now, we'll skip this test
	b.Skip("Custom TCP server not yet implemented")
}

// Memory allocation benchmarks
func BenchmarkIPMarshal_Allocs(b *testing.B) {
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

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ipPacket.Marshal()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPMarshal_Allocs(b *testing.B) {
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

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tcpPacket.MarshalWithChecksum(srcAddr, dstAddr)
	}
}

// Throughput benchmarks
func BenchmarkThroughput_IPPackets(b *testing.B) {
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

	b.ResetTimer()
	b.ReportAllocs()

	totalBytes := 0
	for i := 0; i < b.N; i++ {
		data, err := ipPacket.Marshal()
		if err != nil {
			b.Fatal(err)
		}
		totalBytes += len(data)
	}

	b.ReportMetric(float64(totalBytes)/float64(b.N), "bytes/packet")
}

// Latency benchmarks
func BenchmarkLatency_IPParse(b *testing.B) {
	addresses := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.1.1.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := addresses[i%len(addresses)]
		start := time.Now()
		_, _, err := ip.ParseIPAddress(addr)
		if err != nil {
			b.Fatal(err)
		}
		latency := time.Since(start)
		b.ReportMetric(float64(latency.Nanoseconds()), "ns/parse")
	}
}
