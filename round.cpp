/*
 * Implementation of the ... class for AES Encryption
 *
 * AES Encryption
 * Mark Wesley Harris
 * April 2019
 */

#include "round.h"

Round::Round() {}

/* constructor: verbose */
Round::Round(char *key, char *data, int index) {
    strncpy(this->key, key, KEY_SIZE + 1);
    strncpy(this->data, data, DATA_SIZE + 1);
    this->index = index;
}

/* constructor: clone a Round */
Round::Round(const Round &R) {
    strncpy(key, R.key, KEY_SIZE + 1);
    strncpy(data, R.data, DATA_SIZE + 1);
    index = R.index;
}

/* Substitute Bytes protocol */
void SubstituteBytes() {}

/* Shift Rows protocol */
void ShiftRows() {}

/* Mix Columns protocol */
void MixColumns() {}

/* prints information about this round */
void Round::print() {
    printf("\nROUND %d:\nKey: %s\nData: %s\n", index, key, data);
}
