package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ethPIPv6   = 0x86dd
	sourcePort = 43000
)

func checksum(data []byte) uint16 {
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	var sum uint32
	for index := 0; index < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func parseMAC(value string) net.HardwareAddr {
	address, err := net.ParseMAC(value)
	if err != nil || len(address) != 6 {
		panic("invalid destination MAC")
	}
	return address
}

func extensionHeaders(kind string) (byte, []byte) {
	pad := []byte{1, 4, 0, 0, 0, 0}
	switch kind {
	case "hbh":
		return 0, append([]byte{17, 0}, pad...)
	case "dest":
		return 60, append([]byte{17, 0}, pad...)
	case "chain":
		hbh := append([]byte{60, 0}, pad...)
		dest := append([]byte{17, 0}, pad...)
		return 0, append(hbh, dest...)
	default:
		panic("kind must be hbh, dest, or chain")
	}
}

func main() {
	if len(os.Args) != 7 {
		fmt.Fprintln(os.Stderr, "usage: ipv6-ext-probe <iface> <src-ip> <dst-ip> <dst-mac> <hbh|dest|chain> <dst-port>")
		os.Exit(2)
	}
	device, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		panic(err)
	}
	sourceIP := net.ParseIP(os.Args[2]).To16()
	destinationIP := net.ParseIP(os.Args[3]).To16()
	if sourceIP == nil || destinationIP == nil || strings.Contains(os.Args[2], ".") || strings.Contains(os.Args[3], ".") {
		panic("IPv6 address required")
	}
	destinationMAC := parseMAC(os.Args[4])
	destinationPort, err := strconv.Atoi(os.Args[6])
	if err != nil || destinationPort < 1 || destinationPort > 65535 {
		panic("invalid destination port")
	}

	receiver, err := net.ListenUDP("udp6", &net.UDPAddr{IP: sourceIP, Port: sourcePort})
	if err != nil {
		panic(err)
	}
	defer receiver.Close()
	if err := receiver.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		panic(err)
	}

	payload := []byte("aria-ipv6-extension-header-probe")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], uint16(destinationPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	pseudo := make([]byte, 40+len(udp))
	copy(pseudo[0:16], sourceIP)
	copy(pseudo[16:32], destinationIP)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = 17
	copy(pseudo[40:], udp)
	binary.BigEndian.PutUint16(udp[6:8], checksum(pseudo))

	nextHeader, extensions := extensionHeaders(os.Args[5])
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(extensions)+len(udp)))
	ipv6[6] = nextHeader
	ipv6[7] = 64
	copy(ipv6[8:24], sourceIP)
	copy(ipv6[24:40], destinationIP)
	frame := append([]byte{}, destinationMAC...)
	frame = append(frame, device.HardwareAddr...)
	frame = append(frame, 0x86, 0xdd)
	frame = append(frame, ipv6...)
	frame = append(frame, extensions...)
	frame = append(frame, udp...)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPIPv6)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	address := &syscall.SockaddrLinklayer{Ifindex: device.Index, Protocol: htons(ethPIPv6)}
	if err := syscall.Sendto(fd, frame, 0, address); err != nil {
		panic(err)
	}

	buffer := make([]byte, 2048)
	count, _, err := receiver.ReadFromUDP(buffer)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(buffer[:count], payload) {
		panic("echo mismatch")
	}
	fmt.Printf("extension=%s echo_bytes=%d\n", os.Args[5], count)
}

func htons(value int) uint16 {
	return uint16((value&0xff)<<8 | (value>>8)&0xff)
}
