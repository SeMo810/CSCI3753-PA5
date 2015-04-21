# Makefile for PA 5.
# Adapted from the Makefile provided with the handout.
# Author: Sean Moss (semo0788@colorado.edu)

CC = gcc

CFLAGSFUSE = `pkg-config fuse --cflags`
LLIBSFUSE = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall -Wextra
LFLAGS = -g -Wall -Wextra


