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
the policy rules for the monitoring plugins project? (See the `CODING`
file in the source distribution, it is mostly source code presentation
details.) Do they accept
plugins written in Go? TODO: is it possible to follow exactly the
rules of the Nagios API in Go (command-line arguments, for instance?)
TODO: once done, publish on [Monitoring Exchange](http://monitoringexchange.org)

Second possibility: C and [getdns](https://getdnsapi.net/). TODO:
see how to extract key and cert info from a session. Do a second
connection with GnuTLS (there is a risk to go to a different server…)
Or ask getdns to provide the raw cert in the JSON answer (TODO: format
wishlist report) TODO: a good
example in C? Probably use one of the monitoring
plugins. `check_dummy.c` is a good starting point (specially for the
standard command-line arguments), `check_http.c` a more complete
one. An advantage of using C is that we may rely on monitoring
plugins' utilities such as the `np_net_ssl_check_cert()` function in
`plugins/sslutils.c`, to check the expiration date. To get the RTT,
getdns can do it (`return_call_reporting` extension).


## Requirments

Must be able to specify: resolver, of course, but also DNS query name,
DNS Query Type, expiration date for the cert (like the
[check_http plugin](https://www.monitoring-plugins.org/doc/man/check_http.html)),
the pinned key… Bonus: being able to test the TLS configuration (no
weak cipher, etc) Bonus: check the answer (mandatory content).

Must display the answer, and the RTT. 
