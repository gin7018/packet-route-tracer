package main

import (
	"fmt"
	"net"
	"os"
)

const (
	HOST = "localhost"
	PORT = "5000"
	TYPE = "tcp"
)

func main() {
	server, _ := net.Listen(TYPE, HOST+":"+PORT)
	fmt.Println("server started. listening on ", HOST, ":", PORT)

	defer server.Close()
	for {
		connection, err := server.Accept()
		if err != nil {
			os.Exit(1)
		}
		fmt.Println("client connection from addr = ", connection.RemoteAddr())

		buffer := make([]byte, 1024)
		msg_len, _ := connection.Read(buffer)

		fmt.Println("received: ", string(buffer[:msg_len]))
		connection.Close()

	}

}
