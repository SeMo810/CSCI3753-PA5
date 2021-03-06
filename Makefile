# Makefile for PA 5.
# Adapted from the Makefile provided with the handout.
# Author: Sean Moss (semo0788@colorado.edu)

CC = gcc

CFLAGSFUSE = `pkg-config fuse --cflags`
LLIBSFUSE = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall -Wextra
LFLAGS = -g -Wall -Wextra

.PHONY: all clean

all: pa5-encfs

pa5-encfs: pa5-encfs.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL)

pa5-encfs.o: pa5-encfs.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

aes-crypt.o: aes-crypt.c aes-crypt.h
	$(CC) $(CFLAGS) $<

clean:
	rm -f *.o
	rm -f pa5-encfs
