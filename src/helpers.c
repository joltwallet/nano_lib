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

void int_to_char_array(unsigned char *char_arr, uint32_t data){
    // Converts an int into a char array of 32 bits
    for(int i=3; i>=0; i--){
        char_arr[i] = data & 0xFF;
        data >>= 8;
    }
    sodium_memzero(&data, sizeof(data));
}

void nl_generate_seed(uint256_t seed_bin){
    // Generates a random 32-long array (256 bits) of random data into seed_bin
    uint32_t rand_buffer;

    for(uint8_t i=0; i<8; i++){
        rand_buffer = randombytes_random();
        int_to_char_array(seed_bin + 4*i, rand_buffer);
    }
    sodium_memzero(&rand_buffer, sizeof(rand_buffer));
}

