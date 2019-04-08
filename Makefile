CPP=g++
CFLAGS=-g -Wall

all: aes_encrypt

aes_encrypt:
	$(CPP) $(CFLAGS) aes.cpp -o encrypt -lm

aes_multiple:
	$(CPP) $(CFLAGS) aes_multiple.cpp -o comparison -lm

clean: 
	rm encrypt comparision
