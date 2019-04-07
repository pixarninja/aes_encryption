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

/* Definition of input key */
unsigned int key[16] = { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98 };
/* Round Constant definition */
unsigned char RC[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
/* Expanded key, 44 4-byte words */
unsigned int w[44];

/* Generate S-Box (taken from https://en.wikipedia.org/wiki/Rijndael_S-box) */
void InitializeSbox() {
    uint8_t p = 1, q = 1;
    
    /* Loop invariant: p * q == 1 in the Galois field */
    do {
        /* Multiply p by 3 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        /* Divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        /* Compute the affine transformation */
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

        sbox[p] = (char)(xformed ^ 0x63);
    } while (p != 1);

    /* 0 is a special case since it has no inverse */
    sbox[0] = (char)0x63;
}

/* Given an input byte, return the corresponding output byte from the S-Box */
unsigned int CalculateSboxValue(unsigned int input) {
    int row = (input >> 4) & 0xF;
    int col = input & 0xF;

    return sbox[row * 16 + col];
}

/* Print the calculated S-Box so it can be verified */
void PrintSbox() {
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

/* SubWord Protocol */
unsigned int SubWord(unsigned int w) {
    unsigned int out = 0;
    int i;

    /* Perform a byte substitution using the S-Box */
    for(i = 0; i < 4; i++) {
        /* Isolate the byte being used */
        unsigned int tmp = (w >> (24 - i * 8)) & 0xFF;

        /* Calculate the subsituted byte and store in out */
        unsigned int input = tmp;
        int row = (tmp >> 4) & 0xF;
        int col = tmp & 0xF;
        tmp = CalculateSboxValue(tmp);
        out |= (tmp << (24 - i * 8));

        //printf("... S-Box(%02x)[%01x][%01x] = %02x, out = %x\n", input, row, col, tmp, out);
    }

    return out;
}

/* RotWord Protocol */
unsigned int RotWord(unsigned int w) {
    /* Isolate B0 */
    unsigned int tmp = (w >> 24) & 0xFF;

    /* Shift w to B1 B2 B3 00 */
    w = w << 8;

    /* Complete rotation to B1 B2 B3 B0 */
    return w | tmp;
}

void ExpandKey() {
    unsigned int tmp;
    int i;
    int counter = 1;

    /* Manually set the first 4 words in the expanded key */
    for(i = 0; i < 4; i++) {
        w[i] = (key[4*i] << 24) | (key[4*i + 1] << 16) | (key[4*i + 2] << 8) | key[4*i + 3];
    }

    printf("\nAuxiliary Function:\n--------------------------------\n");

    /* Generate the rest of the expanded key */
    for(i = 4; i < 44; i++) {
        tmp = w[i - 1];
        if(i % 4 == 0) {
            /* Substitute and rotate */
            tmp = RotWord(tmp);
            printf("RotWord (w%d) = %02hhx %02hhx %02hhx %02hhx = x%d\n", i - 1, (tmp >> 24) & 0xFF, (tmp >> 16) & 0xFF, (tmp >> 8) & 0xFF, tmp & 0xFF, counter);

            tmp = SubWord(tmp);
            printf("SubWord (x%d) = %02hhx %02hhx %02hhx %02hhx = y%d\n", counter, (tmp >> 24) & 0xFF, (tmp >> 16) & 0xFF, (tmp >> 8) & 0xFF, tmp & 0xFF, counter);

            /* The three rightmost bytes are always 0 */
            printf("Rcon (%d) = %02hhx 00 00 00\n", i/4, RC[i/4 - 1]);
            tmp = tmp ^ (RC[i / 4 - 1] << 24);
            printf("y%d ^ Rcon (%d) = %02hhx %02hhx %02hhx %02hhx = z%d\n\n", counter, RC[i/4], (tmp >> 24) & 0xFF, (tmp >> 16) & 0xFF, (tmp >> 8) & 0xFF, tmp & 0xFF, counter);
        }

        w[i] = w[i - 4] ^ tmp;
    }
}

void PrintExpandedKey() {
    printf("\nExpanded Key:\n-----------------\n");

    int i;
    for(i = 0; i < 44; i++) {
        printf("w%d = %02hhx %02hhx %02hhx %02hhx\n", i, (w[i] >> 24) & 0xFF, (w[i] >> 16) & 0xFF, (w[i] >> 8) & 0xFF, w[i] & 0xFF);
        if((i + 1) % 4 == 0 && i > 0) {
            printf("\n");
        }
    }
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
    InitializeSbox();
    PrintSbox();

    /* Expand Key */
    ExpandKey();
    PrintExpandedKey();

    return 0;
}
