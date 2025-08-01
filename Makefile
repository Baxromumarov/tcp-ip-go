# Name of the final binary
CLIENT_BINARY_NAME=client
SERVER_BINARY_NAME=server

# Default target: build and run
all: build run

# Build the binary
build:
	go build -o $(CLIENT_BINARY_NAME) client.go
	go build -o $(SERVER_BINARY_NAME) server.go

# Run the binary with root privileges
run-client:
	sudo ./$(CLIENT_BINARY_NAME)
run-server:
	sudo ./$(SERVER_BINARY_NAME)
# Clean up binary
clean:
	rm -f $(CLIENT_BINARY_NAME)	
	rm -f $(SERVER_BINARY_NAME)	
