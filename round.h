/*
 * Definition of the Round class for AES Encryption
 *
 * AES Encryption
 * Mark Wesley Harris
 * April 2019
 */

#ifndef ROUND_H
#define ROUND_H

#define KEY_SIZE 32
#define PT_SIZE 32
#define DATA_SIZE 256

#include <stdio.h>
#include <string.h>
#include <math.h>

class Round {

    public:
        char *key;
        char *data;
        int index;

        //////////////////
        // CONSTRUCTORS //
        //////////////////

        Round();

        /* constructor: verbose */
        Round(char *key, char *data, int index);

        /* constructor: clone a Round */
        Round(const Round &R);

        /////////////
        // METHODS //
        /////////////

        /* Substitute Bytes protocol */
        void SubstituteBytes();

        /* Shift Rows protocol */
        void ShiftRows();

        /* Mix Columns protocol */
        void MixColumns();

        /* prints information about this round */
        void print();
};

#endif
