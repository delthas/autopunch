package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

const flushInterval = 15 * time.Second

type connection struct {
	port    int
	natPort int
	time    time.Time
}

var connections = make(map[[4]byte][]connection)

const version = "0.0.1"

const defaultPort = 14763

func main() {
	fmt.Println("autopunch relay v" + version)
	fmt.Println()

	var port int
	flag.IntVar(&port, "port", defaultPort, "relay listen port")
	flag.Parse()

	c, err := net.ListenUDP("udp4", &net.UDPAddr{
		Port: port,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	flushTime := time.Now()

	buffer := make([]byte, 4096)
	for {
		now := time.Now()
		if now.Sub(flushTime) > flushInterval {
			flushTime = now
			for k, v := range connections {
				for i := 0; i < len(v); i++ {
					c := v[i]
					if now.Sub(c.time) > flushInterval {
						v[i] = v[len(v)-1]
						i--
						v = v[:len(v)-1]
					}
				}
				if len(v) == 0 {
					delete(connections, k)
				}
			}
		}
		n, addr, err := c.ReadFromUDP(buffer)
		if err != nil {
			// err is thrown if the buffer is too small
			continue
		}
		if n != 2 && n != 8 {
			continue
		}
		var senderIp [4]byte
		if senderIpSlice := addr.IP.To4(); senderIpSlice == nil {
			continue
		} else {
			copy(senderIp[:], senderIpSlice)
		}
		if n == 2 {
			senderPort := int(binary.BigEndian.Uint16(buffer[:2]))
			addConnection(senderIp, senderPort, addr.Port)
		} else if n == 8 {
			senderPort := int(binary.BigEndian.Uint16(buffer[:2]))
			addConnection(senderIp, senderPort, addr.Port)

			var ip [4]byte
			copy(ip[:], buffer[2:6])
			v, ok := connections[ip]
			if !ok {
				continue
			}
			port := int(binary.BigEndian.Uint16(buffer[6:8]))

			var target *connection

			for _, conn := range v {
				if conn.port == port { // client sending to internal server port
					target = &conn
				}
			}
			if target == nil {
				for _, conn := range v {
					if conn.natPort == port { // client sending to external server port
						target = &conn
					}
				}
			}
			if target == nil { // client sending to unknown address
				continue
			}

			var payload [8]byte

			// send nat mapping to client
			payload[0] = byte(target.port >> 8)
			payload[1] = byte(target.port)
			payload[2] = byte(target.natPort >> 8)
			payload[3] = byte(target.natPort)
			copy(payload[4:8], ip[:])
			c.WriteToUDP(payload[:], addr)

			// send nat mapping to server
			payload[0] = byte(senderPort >> 8)
			payload[1] = byte(senderPort)
			payload[2] = byte(addr.Port >> 8)
			payload[3] = byte(addr.Port)
			copy(payload[4:8], senderIp[:])
			c.WriteToUDP(payload[:], &net.UDPAddr{
				IP:   net.IP(ip[:]),
				Port: target.natPort,
			})
		}
	}
}

func addConnection(ip [4]byte, port int, natPort int) {
	var v []connection
	if c, ok := connections[ip]; !ok {
		v = make([]connection, 0, 4)
		connections[ip] = v
	} else {
		v = c
	}
	for i, c := range v {
		if c.port != port {
			continue
		}
		v[i].natPort = natPort
		v[i].time = time.Now()
		return
	}
	connections[ip] = append(v, connection{
		port:    port,
		natPort: natPort,
		time:    time.Now(),
	})
}
