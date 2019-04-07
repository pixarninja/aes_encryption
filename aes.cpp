/*
 * Main program for the AES Encryption project
 *
 * AES Encryption
 * Mark Wesley Harris
 * April 2019
 */

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#include "round.h"

using namespace std;

/* Reference to S-BOX table. */
uint8_t sbox[256];

/* Definition of key */
char *key = "0f1571c947d9e8591cb7add6af7f6798";

/* Generate S-Box (taken from https://en.wikipedia.org/wiki/Rijndael_S-box). */
void initialize_aes_sbox() {
    uint8_t p = 1, q = 1;
    
    /* Loop invariant: p * q == 1 in the Galois field. */
    do {
        /* multiply p by 3 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        /* Divide q by 3 (equals multiplication by 0xf6). */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        /* Compute the affine transformation. */
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

        sbox[p] = (char)(xformed ^ 0x63);
    } while (p != 1);

    /* 0 is a special case since it has no inverse. */
    sbox[0] = (char)0x63;
}

/* Print the calculated S-Box so it can be verified */
void print_sbox() {
    printf("Calculated S-Box:\n-----------------------------------------------");

    int i = 0;
    for(; i < 256; i++) {
        if(i % 16 == 0) {
            printf("\n");
        }
        printf("%02X ", sbox[i] & 0xff);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("\nPlease enter a plaintext to encrypt in the format of './encrypt <16-character plaintext>'. Please try again.\n\nExiting Program.\n\n");
        return 1;
    }
    char *pt = new char[PT_SIZE + 1];
    strncpy(pt, argv[1], PT_SIZE);
    pt[PT_SIZE] = '\0';

    printf("\nThe plaintext you entered was: %s\n\n", pt);

    /* Initialize S-Box */
    initialize_aes_sbox();
    print_sbox();

    return 0;
}
