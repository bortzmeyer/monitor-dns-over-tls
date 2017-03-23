# monitor-dns-over-tls
Monitoring plugins for DNS-over-TLS servers

A project for the [IETF 98 Hackathon](https://www.ietf.org/hackathon/98-hackathon.html).

DNS-over-TLS is specified in
[RFC 7858](https://www.rfc-editor.org/info/rfc7858).

The idea is to allow DNS-over-TLS service monitoring, creating a
[monitoring plugin](https://www.monitoring-plugins.org/) (suitable for [Nagios](https://www.nagios.org/)
or compatible like [Icinga](https://www.icinga.com/)). 

## Choices

First possibility: use [Go](https://golang.org/) because it has both a
[nice DNS library](https://miek.nl/2014/August/16/go-dns-package/) and
a
[good TLS standard package](https://golang.org/pkg/crypto/tls/). TODO:
see how to extract key and cert info from a session. TODO: what are
the policy rules for the monitoring plugins project? Do they accept
plugins written in Go? TODO: is it possible to follow exactly the
rules of the Nagios API in Go (command-line arguments, for instance?)

Second possibility: C and [getdns](https://getdnsapi.net/). TODO:
see how to extract key and cert info from a session. TODO: a good
example in C? Probably use one of the monitoring plugins.

## Requirments

Must be able to specify: expiration date for the cert (like the [check_http plugin](https://www.monitoring-plugins.org/doc/man/check_http.html)), the qname, qtype, the pinned key… Bonus: being able to test the TLS configuration (no weak cipher, etc)
