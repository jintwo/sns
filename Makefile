CC=cc
CFLAGS=-I./libuv/include -I./jansson/include -g -c -Wall
LDFLAGS=-L./libuv/lib -L./jansson/lib -luv -ljansson

.PHONY: clean

server: server.o dns.o utils.o
	$(CC) $(LDFLAGS) -o $@ $?

clean:
	rm -rf *.o server test

%.o: %.c
	$(CC) $(CFLAGS) -c $?

all: libs test server

libs:
	git submodule update --init
	cd libuv && sh autogen.sh && ./configure --prefix=`pwd` && make && make install
	cd jansson && autoreconf -i && ./configure --prefix=`pwd` && make && make install

test: test.o utils.o
	$(CC) $(LDFLAGS) -o $@ $?
	./test
	@echo ""
