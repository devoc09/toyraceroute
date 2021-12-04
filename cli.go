package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	ExitCodeOk    = 0
	ExitCodeError = 1
	noRecordError = 2
)

type CLI struct {
	outStream, errStream io.Writer
}

func (c *CLI) Run(args []string) int {
	host := os.Args[1]
	// dst domain name -> dst IP
	ips, err := net.LookupIP(host)
	if err != nil {
		fmt.Fprintf(c.errStream, "Error! can't resolve name to IP\n%s\n", err)
		return ExitCodeError
	}
	var dstIPAddr net.IPAddr
	for _, ip := range ips {
		if ip.To4() != nil {
			dstIPAddr.IP = ip
			fmt.Printf("Using %v for tracing an IP packet route to %s\n", dstIPAddr.IP, host)
			break
		}
	}
	if dstIPAddr.IP == nil {
		// log.Fatal("no A record found")
		fmt.Fprintf(c.errStream, "No A record found")
		return noRecordError
	}

	// Listen Packet at 0.0.0.0 local network address
	conn, err := net.ListenPacket("ip4:1", "0.0.0.0")
	if err != nil {
		// log.Fatal(err)
		fmt.Fprintf(c.errStream, "Failed listen packet at 0.0.0.0\n%s\n", err)
		return ExitCodeError
	}

	defer conn.Close()

	// packet connection using conn
	p := ipv4.NewPacketConn(conn)
	// set per packet IP-level socket option
	if err := p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		// log.Fatal(err)
		fmt.Fprintf(c.errStream, "Failed set IP option\n%s\n", err)
		return ExitCodeError
	}
	// set icmp message body
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	rb := make([]byte, 1500)
	for i := 1; i <= 64; i++ {
		wm.Body.(*icmp.Echo).Seq = i
		wb, err := wm.Marshal(nil)
		if err != nil {
			log.Fatal(err)
		}
		if err := p.SetTTL(i); err != nil {
			log.Fatal(err)
		}
		begin := time.Now()
		if _, err := p.WriteTo(wb, nil, &dstIPAddr); err != nil {
			log.Fatal(err)
		}
		if err := p.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			log.Fatal(err)
		}
		n, cm, peer, err := p.ReadFrom(rb)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				fmt.Printf("%v\t*\n", i)
				continue
			}
			log.Fatal(err)
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			log.Fatal(err)
		}
		rtt := time.Since(begin)
		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded:
			names, _ := net.LookupAddr(peer.String())
			fmt.Printf("%d\t%v %+v %v\n\t%+v\n", i, peer, names, rtt, cm)
		case ipv4.ICMPTypeEchoReply:
			names, _ := net.LookupAddr(peer.String())
			fmt.Printf("%d\t%v %+v %v\n\t%+v\n", i, peer, names, rtt, cm)
			return ExitCodeOk
		default:
			log.Printf("unknown ICMP message: %+v\n", rm)
		}
	}
	return ExitCodeError
}
