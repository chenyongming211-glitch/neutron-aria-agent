package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: ipv6-udp-probe <ipv6> <port> <bytes>")
		os.Exit(2)
	}
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	size, err := strconv.Atoi(os.Args[3])
	if err != nil || size < 1 || size > 65507 {
		panic("invalid payload size")
	}
	remote := &net.UDPAddr{IP: net.ParseIP(os.Args[1]), Port: port}
	connection, err := net.DialUDP("udp6", nil, remote)
	if err != nil {
		panic(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		panic(err)
	}
	payload := bytes.Repeat([]byte("A"), size)
	written, err := connection.Write(payload)
	if err != nil {
		panic(err)
	}
	buffer := make([]byte, size+1)
	read, err := connection.Read(buffer)
	if err != nil {
		panic(err)
	}
	if written != size || read != size || !bytes.Equal(payload, buffer[:read]) {
		panic("echo mismatch")
	}
	fmt.Printf("echo_bytes=%d\n", read)
}
