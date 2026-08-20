package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

const ethPIPv6 = 0x86dd

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

func htons(value int) uint16 {
	return uint16((value&0xff)<<8 | (value>>8)&0xff)
}

func main() {
	if len(os.Args) != 8 {
		fmt.Fprintln(os.Stderr, "usage: ipv6-ra-sender <iface> <src-link-local> <src-mac> <dst-link-local> <dst-mac> <prefix> <lifetime>")
		os.Exit(2)
	}
	device, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		panic(err)
	}
	sourceIP := net.ParseIP(os.Args[2]).To16()
	sourceMAC, err := net.ParseMAC(os.Args[3])
	if err != nil {
		panic(err)
	}
	destinationIP := net.ParseIP(os.Args[4]).To16()
	destinationMAC, err := net.ParseMAC(os.Args[5])
	if err != nil {
		panic(err)
	}
	_, prefix, err := net.ParseCIDR(os.Args[6])
	if err != nil {
		panic(err)
	}
	lifetime, err := strconv.Atoi(os.Args[7])
	if err != nil || lifetime < 0 || lifetime > 9000 {
		panic("invalid router lifetime")
	}

	icmp := make([]byte, 56)
	icmp[0] = 134
	icmp[4] = 64
	binary.BigEndian.PutUint16(icmp[6:8], uint16(lifetime))
	icmp[16] = 1
	icmp[17] = 1
	copy(icmp[18:24], sourceMAC)
	icmp[24] = 3
	icmp[25] = 4
	icmp[26] = 64
	icmp[27] = 0xc0
	binary.BigEndian.PutUint32(icmp[28:32], 300)
	binary.BigEndian.PutUint32(icmp[32:36], 120)
	copy(icmp[40:56], prefix.IP.To16())
	pseudo := make([]byte, 40+len(icmp))
	copy(pseudo[0:16], sourceIP)
	copy(pseudo[16:32], destinationIP)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = 58
	copy(pseudo[40:], icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(pseudo))

	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(icmp)))
	ipv6[6] = 58
	ipv6[7] = 255
	copy(ipv6[8:24], sourceIP)
	copy(ipv6[24:40], destinationIP)
	frame := append([]byte{}, destinationMAC...)
	frame = append(frame, sourceMAC...)
	frame = append(frame, 0x86, 0xdd)
	frame = append(frame, ipv6...)
	frame = append(frame, icmp...)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPIPv6)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	address := &syscall.SockaddrLinklayer{Ifindex: device.Index, Protocol: htons(ethPIPv6)}
	for count := 0; count < 3; count++ {
		if err := syscall.Sendto(fd, frame, 0, address); err != nil {
			panic(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Printf("ra_lifetime=%d sent=3\n", lifetime)
}
