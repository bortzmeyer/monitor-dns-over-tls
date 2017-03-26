CFLAGS=-O0 -g -std=c99 -Wall -Wextra
LDFLAGS=-L/usr/local/lib -lgetdns -L/usr/lib -lgnutls
#LDFLAGS=-lgetdns
EXES=check-dns-with-getdns getdns-tls godns-tls

all: ${EXES}

%: %.c
	${CC} ${CCFLAGS} -c -o $@ $^
	${CC} -o $@ $^ ${LDFLAGS}

%.o: %c
	${CC} ${CCFLAGS} -c -o $@ $^

%: %.o
	${CC} -o $@ $^ ${LDFLAGS}

%: %.go
	go build $^

clean:
	rm -f ${EXES} *~ *.o 

install: check-dns-with-getdns
	cp check-dns-with-getdns /usr/lib/nagios/plugins/check_dns_with_getdns
