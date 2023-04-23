# File: Makefile
# By: Andy Sayler <www.andysayler.com>
# Adopted from work by: Chris Wailes <chris.wailes@gmail.com>
# Project: CSCI 3753 Programming Assignment 5
# Creation Date: 2010/04/06
# Modififed Date: 2012/04/12
# Description:
#	This is the Makefile for PA5.

CC           = gcc
obj          = encfuse.o file-crypt.o access-control.o
CFLAGSFUSE   = `pkg-config fuse --cflags`
LLIBSFUSE    = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -std=c11 -g -Wall -Wextra
LFLAGS = -g -std=c11 -Wall -Wextra

ENCFUSE = encfuse
ACCESS_CONTROL = access-control
FILE_CRYPT = file-crypt

.PHONY: all enc-fuse clean

all: enc-fuse

enc-fuse: $(ENCFUSE)

# -fsanitize=address
encfuse: $(obj)
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) -lcrypto

encfuse.o: encfuse.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

access-control.o: access-control.c
	$(CC) $(CFLAGS) $<

file-crypt.o: file-crypt.c
	$(CC) $(CFLAGS) $<

clean:
	rm -f $(ENCFUSE)
	rm -f $(ACCESS_CONTROL)
	rm -f $(FILE_CRYPT)
	rm -f *.o
	rm -f *~
	rm -f *.log



