CC=cc
CFLAGS=-g -c -Wall
LDFLAGS=-luv -ljansson

all: test server

test: test.o utils.o
	$(CC) $(LDFLAGS) -o $@ test.o utils.o
	./test
	@echo ""

server: server.o utils.o
	$(CC) $(LDFLAGS) -o $@ server.o utils.o

test.o: test.c
	$(CC) $(CFLAGS) -c test.c

utils.o: utils.c
	$(CC) $(CFLAGS) -c utils.c

server.o: server.c
	$(CC) $(CFLAGS) -c server.c

clean:
	rm -rf *.o server test
