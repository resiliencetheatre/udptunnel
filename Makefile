INCLUDE = -I./include
CC = gcc
#CC = /home/felipe/Sources/OpenWrt-SDK-brcm47xx-2.6-for-Linux-i686/staging_dir_mipsel/bin/mipsel-linux-gcc
CFLAGS = -Wall
LDLIBS = -lcrypto

all: socket.o tun.o util.o client.o server.o binn.o log.o ini.o
	$(CC) socket.o tun.o util.o client.o binn.o log.o ini.o -o client $(LDLIBS)
	$(CC) socket.o tun.o util.o server.o binn.o log.o ini.o -o server $(LDLIBS)

socket.o: socket.c include/utun/socket.h include/utun/tunnel_packet.h
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

tun.o: tun.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

util.o: util.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

client.o: client.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

server.o: server.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

binn.o: binn.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

log.o: log.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

ini.o: ini.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<
clean:
	rm -f *.o client server tests/test_transport tests/test_transport_sanitize

# -----------------------------------------------------------
# Install and uninstall
# -----------------------------------------------------------

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 server  $(DESTDIR)$(BINDIR)/
	install -m 0755 client $(DESTDIR)$(BINDIR)/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/server
	rm -f $(DESTDIR)$(BINDIR)/client

.PHONY: all clean install uninstall

TEST_BIN = tests/test_transport
$(TEST_BIN): tests/test_transport.c socket.c log.c include/utun/socket.h include/utun/tunnel_packet.h
	$(CC) $(CFLAGS) $(INCLUDE) tests/test_transport.c socket.c log.c -o $@ $(LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

sanitize:
	$(CC) -Wall -g -fsanitize=address,undefined $(INCLUDE) tests/test_transport.c socket.c log.c -o tests/test_transport_sanitize $(LDLIBS)
	./tests/test_transport_sanitize

.PHONY: test sanitize
