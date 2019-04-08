CPP=g++
CFLAGS=-g -Wall

all: aes_encrypt

aes_encrypt:
	$(CPP) $(CFLAGS) aes.cpp -o encrypt -lm

clean: 
	rm encrypt
