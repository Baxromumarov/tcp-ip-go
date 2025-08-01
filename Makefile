# FOR TESTING ONLY
CLIENT_BINARY_NAME=client
SERVER_BINARY_NAME=server

all: build run

build:
	go build -o $(CLIENT_BINARY_NAME) client.go
	go build -o $(SERVER_BINARY_NAME) server.go

run-client:
	sudo ./$(CLIENT_BINARY_NAME)
run-server:
	sudo ./$(SERVER_BINARY_NAME)
clean:
	rm -f $(CLIENT_BINARY_NAME)	
	rm -f $(SERVER_BINARY_NAME)	
