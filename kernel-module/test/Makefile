# Makefile for BPF Verifier Rust test programs

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS =

PROGS = test_ioctl test_simple

.PHONY: all clean

all: $(PROGS)

test_ioctl: test_ioctl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_simple: test_simple.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGS)
