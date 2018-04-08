#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"

#include "nano_lib.h"
#include "helpers.h"

/* The n varieties of these case functions copies up to the null terminator or
 * n characters. These should take in null terminated strings, but not necessary
 * in the n cases*/

void strupper(char *s){
    /* Converts a null-terminated string to uppercase */
    for(unsigned int c=0; s[c]!='\0'; c++){
        if (s[c] >= 'a' && s[c] <= 'z')
            s[c] = s[c] - 32;   
    }
}

void strnupper(char *s, const int n){
    /* Converts a null-terminated string to uppercase up to n characters*/
    for(unsigned int c=0; c < n; c++){
        if (s[c] >= 'a' && s[c] <= 'z')
            s[c] = s[c] - 32;   
    }
}

void strlower(char *s){
    /* Converts a null-terminated string to lowercase */
    for(unsigned int c=0; s[c]!='\0'; c++){
        if (s[c] >= 'A' && s[c] <= 'Z')
            s[c] = s[c] + 32;
    }
}

void strnlower(char *s, const int n){
    /* Converts a null-terminated string to lowercase up to n characters*/
    for(unsigned int c=0; c <= n; c++){
        if (s[c] >= 'A' && s[c] <= 'Z')
            s[c] = s[c] + 32;
    }
}

void write_be(uint8_t *data, uint32_t x){
	data[0] = x >> 24;
	data[1] = x >> 16;
	data[2] = x >> 8;
	data[3] = x;
    sodium_memzero(&x, sizeof(x));
}

void write_be64(uint8_t *data, uint64_t x){
	data[0] = x >> 56;
	data[1] = x >> 48;
	data[2] = x >> 40;
	data[3] = x >> 32;
	data[4] = x >> 24;
	data[5] = x >> 16;
	data[6] = x >> 8;
	data[7] = x;
    sodium_memzero(&x, sizeof(x));
}


void nl_generate_seed(uint256_t seed_bin){
    // Generates a random 32-long array (256 bits) of random data into seed_bin
    uint32_t rand_buffer;

    for(uint8_t i=0; i<8; i++){
        rand_buffer = randombytes_random();
        memcpy(seed_bin + 4*i, &rand_buffer, sizeof(rand_buffer));
    }
    sodium_memzero(&rand_buffer, sizeof(rand_buffer));
}

