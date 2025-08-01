package main

import (
	"fmt"
	"log"

	"github.com/baxromumarov/http-go/tcp"
)

func main() {
	listener, err := tcp.ListenTCP("127.0.0.1", 8080)
	if err != nil {
		log.Fatalf("Error listening on TCP: %v", err)
	}
	defer listener.Close()

	fmt.Println("TCP server listening on port", listener.LocalPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(conn *tcp.TCPConn) {
	defer conn.Close()
	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		if n > 0 {
			received := string(buf[:n])
			fmt.Printf("Received: %s\n", received)
			// Response is now handled in the TCP layer
		}
	}
}
