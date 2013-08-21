CC=cc
CFLAGS=-I./libuv/include -I./jansson/include -g -c -Wall
LDFLAGS=-L./libuv/lib -L./jansson/lib -luv -ljansson

all: libs test server

libs:
	git submodule update --init
	cd libuv && sh autogen.sh && ./configure --prefix=`pwd` && make && make install
	cd jansson && autoreconf -i && ./configure --prefix=`pwd` && make && make install

test: test.o utils.o
	$(CC) $(LDFLAGS) -o $@ $?
	./test
	@echo ""

server: server.o utils.o
	$(CC) $(LDFLAGS) -o $@ $?

test.o: test.c
	$(CC) $(CFLAGS) -c $?

utils.o: utils.c
	$(CC) $(CFLAGS) -c $?

server.o: server.c
	$(CC) $(CFLAGS) -c $?

clean:
	rm -rf *.o server test
