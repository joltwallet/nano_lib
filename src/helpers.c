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
    char ch;
    for(unsigned int c=0; (ch=s[c]) != '\0'; c++){
        if (ch >= 'a' && ch <= 'z')
            s[c] = s[c] - 32;   
    }
}

void strnupper(char *s, const int n){
    /* Converts a null-terminated string to uppercase up to n characters*/
    char ch;
    for(int c=0; c < n; c++){
        ch = s[c];
        if (ch >= 'a' && ch <= 'z')
            s[c] = s[c] - 32;   
    }
}

void strlower(char *s){
    /* Converts a null-terminated string to lowercase */
    char ch;
    for(unsigned int c=0; (ch=s[c]) != '\0'; c++){
        if (ch >= 'A' && ch <= 'Z')
            s[c] = s[c] + 32;
    }
}

void strnlower(char *s, const int n){
    /* Converts a null-terminated string to lowercase up to n characters*/
    char ch;
    for(int c=0; c <= n; c++){
        ch = s[c];
        if (ch >= 'A' && ch <= 'Z')
            s[c] = s[c] + 32;
    }
}


