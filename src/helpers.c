/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

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
