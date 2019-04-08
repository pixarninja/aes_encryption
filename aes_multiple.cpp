/*
 * Main program for the AES Encryption project
 *
 * AES Encryption
 * Mark Wesley Harris
 * April 2019
 */

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
#define KEY_SIZE 32
#define PT_SIZE 32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <time.h>

using namespace std;

/* Reference to S-BOX table. */
uint8_t sbox[256];

/* Definition of input key */
unsigned int key[16] = { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x1c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98 };
/* Round Constant definition */
unsigned char RC[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
/* Expanded key, 44 4-byte words */
unsigned int w[44];
/* State Block, 4 4-byte words */
unsigned int state[4] = { 0, 0, 0, 0 };
/* Round counter */
int count = 0;
/* Mix Columns encryption matrix */
unsigned int MCE[4] = { 0x02030101, 0x01020301, 0x01010203, 0x03010102 };

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
        tmp = CalculateSboxValue(tmp);
        out |= (tmp << (24 - i * 8));
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

/* Key Expansion Protocol */
void ExpandKey() {
    unsigned int tmp;
    int i;

    /* Manually set the first 4 words in the expanded key */
    for(i = 0; i < 4; i++) {
        w[i] = (key[4*i] << 24) | (key[4*i + 1] << 16) | (key[4*i + 2] << 8) | key[4*i + 3];
    }

    /* Generate the rest of the expanded key */
    for(i = 4; i < 44; i++) {
        tmp = w[i - 1];
        if(i % 4 == 0) {
            /* Substitute and rotate */
            tmp = RotWord(tmp);

            tmp = SubWord(tmp);

            /* The three rightmost bytes are always 0 */
            tmp = tmp ^ (RC[i / 4 - 1] << 24);
        }

        w[i] = w[i - 4] ^ tmp;
    }
}

/* Print the Expanded Key in a readable format */
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

/* Print the State in a readable format */
void PrintState() {
    int i;
    for(i = 0; i < 4; i++) {
        printf("%02x %02x %02x %02x\n", (state[0] >> (24 - 8*i)) & 0xFF, (state[1] >> (24 - 8*i)) & 0xFF, (state[2] >> (24 - 8*i)) & 0xFF, (state[3] >> (24 - 8*i)) & 0xFF);
    }
    printf("\n");
}

/* Print the Round Key in a readable format */
void PrintRoundKey() {
    printf("\n(%d) Round Key:\n--------------\n", count);

    int i;
    int offset = count * 4;
    for(i = 0; i < 4; i++) {
        printf("%02x %02x %02x %02x\n", (w[offset] >> (24 - 8*i)) & 0xFF, (w[offset + 1] >> (24 - 8*i)) & 0xFF, (w[offset + 2] >> (24 - 8*i)) & 0xFF, (w[offset + 3] >> (24 - 8*i)) & 0xFF);
    }
    printf("\n");
}

/* AddRoundKey protocol */
void AddRoundKey() {
    /* XOR each byte of state[] with w[i,j] */
    for(int i = 0; i < 4; i++) {
        state[i] ^= w[i + count * 4];
    }
}

/* SubstituteBytes Protocol */
void SubstituteBytes() {
    int i;
    for(i = 0; i < 4; i++) {
        state[i] = SubWord(state[i]);
    }
}

/* Shift Rows Protocol */
void ShiftRows() {
    int i;
    int j;
    unsigned int row = 0;
    unsigned int tmp = 0;
    unsigned int out = 0;
    int pos = 0;

    /* Keep track of which row is being shifted by i */
    for(i = 1; i < 4; i++) {
        out = 0;

        /* Find row, since it is the ith column of state matrix */
        row = ((state[0] >> (24 - 8*i)) & 0xFF) << 24 | ((state[1] >> (24 - 8*i)) & 0xFF) << 16 | ((state[2] >> (24 - 8*i)) & 0xFF) << 8 | ((state[3] >> (24 - 8*i)) & 0xFF);

        /* Shift each byte accordingly */
        for(j = 0; j < 4; j++) {
            /* Isolate byte */
            tmp = (row >> (24 - 8 * j)) & 0xFF;

            /* Shift byte */
            pos = (3 - j + i) % 4;
            tmp = tmp << 8 * pos;
            out |= tmp;
        }

        /* Store as column i of state matrix */
        unsigned int mask = 0;
        if(i == 1) {
            mask = 0xFF00FFFF;
        }
        else if(i == 2) {
            mask = 0xFFFF00FF;
        }
        else {
            mask = 0xFFFFFF00;
        }
        for(j = 0; j < 4; j++) {
            state[j] = (state[j] & mask) | (((out >> (24 - 8*j)) & 0xFF) << (24 - 8*i));
        }
    }
}

/* Special Matrix Multiplication given a row and column */
unsigned int MultiplyMatrix(unsigned int row, unsigned int col) {
    int i;
    unsigned int m = 0x1B;
    unsigned int r = 0;
    unsigned int c = 0;
    unsigned int tmp = 0;
    unsigned int sum = 0;

    /* Iterate on each element of row and col */
    for(i = 0; i < 4; i++) {
        /* Isolate row and col bytes */
        r = (row >> (24 - 8 * i)) & 0xFF;
        c = (col >> (24 - 8 * i)) & 0xFF;
        tmp = c;

        /* Store the multiplication c * r into sum */
        if(r == 0x02 || r == 0x03) {
            if(c & 0x80) {
                c = (c << 1) ^ m;
            }
            else {
                c = c << 1;
            }
        }
        if(r == 0x03) {
            c = c ^ tmp;
        }
        sum ^= c;
    }

    return sum & 0xFF;
}

/* Mix Columns Protocol */
void MixColumns() {
    int i;
    int j;
    unsigned int tmp;
    unsigned int calculated[4] = { 0, 0, 0, 0 };

    /* Traverse each row of MCE */
    for(i = 0; i < 4; i++) {
        /* Traverse each column of state */
        for(j = 0; j < 4; j++) {
            /* Store isolated byte */
            tmp = MultiplyMatrix(MCE[i], state[j]);

            /* Move byte and store in new state */
            calculated[j] |= tmp << (24 - 8 * i);
        }
    }

    /* Copy calculated matrix to state */
    memcpy(state, calculated, 16);
}

int CompareRounds(unsigned int *a, unsigned int *b) {
    int i;
    int j;
    int diff = 0;

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 32; j++) {
            if (((a[i] >> j) & 1) != ((b[i] >> j) & 1)) { 
                diff++; 
            }
        }
    }

    return diff;
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("\nPlease enter a plaintext to encrypt in the format of './encrypt <16-character plaintext>'. Please try again.\n\nExiting Program.\n\n");
        return 1;
    }

    int i;
    int k;
    char **inputs = new char *[4];
    for(i = 0; i < 4; i++) {
        inputs[i] = new char[PT_SIZE];
        strncpy(inputs[i], argv[1], PT_SIZE);
    }

    /* Parse plaintext */
    unsigned int pt[PT_SIZE / 2];
    for(i = 0; i < PT_SIZE; i += 2) {
        char s[2] = { inputs[0][i], inputs[0][i + 1] };
        sscanf(s, "%x", &(pt[i / 2])); 
    }

    printf("\nThe plaintext you entered was: ");
    for(i = 0; i < PT_SIZE / 2; i++) {
        printf("%02x ", pt[i]);
    }
    printf("\n");

    /* Initialize S-Box */
    InitializeSbox();

    /* Expand Key */
    ExpandKey();

    unsigned int rounds[12][4];
    bool stored = false;
    int diff = 0;
    int byte = 0;
    int num = 0;
    unsigned int bit;

    srand(time(NULL));

    for(k = 0; k < 4; k++) {
        count = 0;

        /* Parse plaintext */
        unsigned int pt[PT_SIZE / 2];
        for(i = 0; i < PT_SIZE; i += 2) {
            char s[2] = { inputs[k][i], inputs[k][i + 1] };
            sscanf(s, "%x", &(pt[i / 2])); 
        }

        /* Parse plaintext into block */
        for(i = 0; i < 4; i++) {
            state[i] = (pt[4*i] << 24) | (pt[4*i + 1] << 16) | (pt[4*i + 2] << 8) | pt[4*i + 3];
        }

        /* Flip a random bit of each extra input */
        if(k > 0) {
            while(true) {
                byte = rand() % 4;

                bit = 0x01;
                num = rand() % 32;
                bit = bit << (31 - num);

                /* Flip bit */
                if ((state[byte] >> num) & 1) { 
                    //state[byte] &= ~bit;
                    continue;
                }
                else {
                    state[byte] |= bit;
                    break;
                }
            }
            printf("\nAltered bit %d of byte %d for input %d\n\n", num, byte, k);

            PrintState();
        }

        /* Initial step into AES chain */
        if(!stored) {
            memcpy(rounds[count], state, 16);
        }
        else {
            printf("\nRound %d:\n", -1);
            printf("%08x%08x%08x%08x\n", rounds[count][0], rounds[count][1], rounds[count][2], rounds[count][3]);
            printf("%08x%08x%08x%08x\n", state[0], state[1], state[2], state[3]);
            diff = CompareRounds(rounds[count], state);
            printf("Bits Different: %d\n", diff);
        }

        AddRoundKey();

        if(!stored) {
            memcpy(rounds[count + 1], state, 16);
        }
        else {
            printf("\nRound %d:\n", count);
            printf("%08x%08x%08x%08x\n", rounds[count + 1][0], rounds[count + 1][1], rounds[count + 1][2], rounds[count + 1][3]);
            printf("%08x%08x%08x%08x\n", state[0], state[1], state[2], state[3]);
            diff = CompareRounds(rounds[count + 1], state);
            printf("Bits Different: %d\n", diff);
        }

        count++;

        /* Start the AES chain */
        for(i = 0; i < 9; i++) {
            SubstituteBytes();

            ShiftRows();

            MixColumns();

            AddRoundKey();

            if(!stored) {
                memcpy(rounds[count + 1], state, 16);
            }
            else {
                printf("\nRound %d:\n", count);
                printf("%08x%08x%08x%08x\n", rounds[count + 1][0], rounds[count + 1][1], rounds[count + 1][2], rounds[count + 1][3]);
                printf("%08x%08x%08x%08x\n", state[0], state[1], state[2], state[3]);
                diff = CompareRounds(rounds[count + 1], state);
                printf("Bits Different: %d\n", diff);
            }

            count++;
        }

        SubstituteBytes();

        ShiftRows();

        AddRoundKey();

        if(!stored) {
            memcpy(rounds[count + 1], state, 16);
        }
        else {
            printf("\nRound %d:\n", count);
            printf("%08x%08x%08x%08x\n", rounds[count + 1][0], rounds[count + 1][1], rounds[count + 1][2], rounds[count + 1][3]);
            printf("%08x%08x%08x%08x\n", state[0], state[1], state[2], state[3]);
            diff = CompareRounds(rounds[count + 1], state);
            printf("Bits Different: %d\n", diff);
        }

        stored = true;
        printf("\n");
    }

    return 0;
}
