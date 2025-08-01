package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/baxromumarov/tcp-ip-go/tcp"
)

func main() {
	tcpServer, err := tcp.DialTCP("127.0.0.1", 8080)
	if err != nil {
		fmt.Println("Error dialing TCP server:", err)
		return
	}
	defer tcpServer.Close()

	fmt.Println("Connected to server at localhost:8080")

	// Read user input from stdin
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter message to send (or 'exit' to quit): ")
	for scanner.Scan() {
		message := scanner.Text()
		if message == "exit" {
			break
		}

		// Send message to server
		_, err := fmt.Fprintf(tcpServer, "%s\n", message)
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			return
		}

		// Read server response
		buf := make([]byte, 1024)
		_, err = tcpServer.Read(buf)
		if err != nil {
			log.Printf("Failed to read response: %v", err)
			return
		}

		fmt.Print("Enter message to send (or 'exit' to quit): ")
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading input: %v", err)
	}
}
