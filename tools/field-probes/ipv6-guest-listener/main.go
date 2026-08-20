package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func serveTCP(errors chan<- error) {
	listener, err := net.Listen("tcp6", "[::]:8080")
	if err != nil {
		errors <- err
		return
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			errors <- err
			return
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func serveUDP(errors chan<- error) {
	connection, err := net.ListenUDP("udp6", &net.UDPAddr{
		IP:   net.IPv6unspecified,
		Port: 1080,
	})
	if err != nil {
		errors <- err
		return
	}
	buffer := make([]byte, 65535)
	for {
		count, remote, err := connection.ReadFromUDP(buffer)
		if err != nil {
			errors <- err
			return
		}
		if count > 0 {
			_, _ = connection.WriteToUDP(buffer[:count], remote)
		}
	}
}

func main() {
	errors := make(chan error, 2)
	go serveTCP(errors)
	go serveUDP(errors)
	fmt.Println("IPv6 TCP/8080 and UDP/1080 listeners ready")
	if err := <-errors; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
