package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type stats struct {
	mu       sync.Mutex
	events   uint64
	bytes    uint64
	lastSeen int64
	path     string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 4 || args[0] != "serve" {
		return fmt.Errorf("usage: %s serve tcp|udp <port> <state-dir>", os.Args[0])
	}
	proto := args[1]
	port, err := strconv.Atoi(args[2])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %s", args[2])
	}
	stateDir := args[3]
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}

	st := &stats{path: filepath.Join(stateDir, fmt.Sprintf("%s_%d.stats", proto, port))}
	switch proto {
	case "tcp":
		return serveTCP(port, st)
	case "udp":
		return serveUDP(port, st)
	default:
		return fmt.Errorf("invalid protocol: %s", proto)
	}
}

func (s *stats) record(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events++
	if n > 0 {
		s.bytes += uint64(n)
	}
	s.lastSeen = time.Now().Unix()

	tmp := s.path + ".tmp"
	body := fmt.Sprintf("events=%d bytes=%d last_seen=%d", s.events, s.bytes, s.lastSeen)
	if err := os.WriteFile(tmp, []byte(body), 0600); err == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func serveTCP(port int, st *stats) error {
	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("tcp listener ready port=%d\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			st.record(0)
			buf := make([]byte, 64*1024)
			for {
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := c.Read(buf)
				if n > 0 {
					st.record(n)
					_, _ = c.Write(buf[:n])
				}
				if err != nil {
					if err == io.EOF {
						return
					}
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						return
					}
					return
				}
			}
		}(conn)
	}
}

func serveUDP(port int, st *stats) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("udp listener ready port=%d\n", port)
	buf := make([]byte, 64*1024)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		st.record(n)
		if n > 0 && remote != nil {
			_, _ = conn.WriteToUDP(buf[:n], remote)
		}
	}
}
