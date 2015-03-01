CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c ssl_common.c
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: client.o ssl_common.o
	$(CC) $(LDFLAGS) -o client client.o ssl_common.o

server: server.o ssl_common.o
	$(CC) $(LDFLAGS) -o server server.o ssl_common.o


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

ssl_common.o: ssl_common.c
	$(CC) $(CFLAGS) -c -o ssl_common.o ssl_common.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

