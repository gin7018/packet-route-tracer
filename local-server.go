package main

import (
	"fmt"
	"net"
	"os"
)

const (
	HOST = "127.0.0.1"
	PORT = "5000"
	TYPE = "tcp"
)

func main() {
	server, _ := net.Listen("tcp", "127.0.0.1:8080")
	fmt.Println("server started. listening on 127.0.0.1:8080")

	for {
		connection, err := server.Accept()
		if err != nil {
			os.Exit(1)
		}

		go handleRequest(connection)
	}

}

func handleRequest(conn net.Conn) {
	fmt.Println("client connection from addr = ", conn.RemoteAddr())

	buffer := make([]byte, 1024)
	msg_len, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("error reading payload: ", err.Error())
	}

	fmt.Println("received: ", string(buffer[:msg_len]))

}
