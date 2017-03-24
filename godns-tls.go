package main

import (
	"flag"
	"fmt"
	"net"
	"crypto/tls"
	"github.com/miekg/dns"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] NAMESERVER-IP ZONE\n", os.Args[0])
		flag.PrintDefaults()
	}
	help := flag.Bool("h", false, "Print help")
	insecure := flag.Bool("k", false, "Do not check the certificate")
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	if len(flag.Args()) != 2 {
		flag.Usage()
		os.Exit(1)
	}
	ns := flag.Arg(0)
	zone := dns.Fqdn(flag.Arg(1))
	m := new(dns.Msg)
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	c := new(dns.Client)
	c.Net = "tcp-tls"
	if *insecure {
		c.TLSConfig = new(tls.Config)
		c.TLSConfig.InsecureSkipVerify = true
	}
	m.Question[0] = dns.Question{zone, dns.TypeDNSKEY, dns.ClassINET}
	m.Id = dns.Id()
	in, rtt, err := c.Exchange(m, net.JoinHostPort(ns, "853"))
	if err == nil && in != nil && len(in.Answer) > 0 {
		fmt.Printf("(time %.3d µs) %d keys. TC=%v\n", rtt/1e3, len(in.Answer), in.Truncated)
	} else {
		if err != nil {
			// TODO proper monitoring plugin formatting
			fmt.Printf("Error in query: %s\n", err)
		} else if in == nil {
			fmt.Printf("No answer received\n")
		} else if len(in.Answer) == 0 {
			fmt.Printf("Empty answer received. TC=%v\n", in.Truncated) // Common by default, since DNSKEY answers can be large
		}
	}
}
