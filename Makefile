CFLAGS=-std=c99 -Wall -Wextra
#LDFLAGS=-L/usr/local/lib -lgetdns
LDFLAGS=-lgetdns

all: getdns-tls

%.o: %c
	${CC} ${CCFLAGS} -c -o $@ $^

%: %.o
	${CC} -o $@ $^ ${LDFLAGS}

