#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libsodium.h"

#include "nano_lib.h"
//#include "translation.h"

#define ADDRESS_DATA_LEN 60

// Helpers for Pub_key to address translation
#define CHECKSUM_LEN 5
#define B_11111 31
#define B_01111 15
#define B_00111  7
#define B_00011  3
#define B_00001  1

nl_err_t nl_public_to_address(char *address_buf, const uint8_t address_buf_len,
        const uint256_t public_key){
    /* Translates a 256-bit binary public key into a NANO/XRB Address.
     * Based on Roosmaa's Ledger S Nano Github
     */
    uint8_t k, i, c;
    uint8_t check[CHECKSUM_LEN];

    crypto_generichash_state state;

    if (address_buf_len < (strlen(ADDRESS_PREFIX) + ADDRESS_DATA_LEN)){
        return E_INSUFFICIENT_BUF;
    }

    crypto_generichash_init(  &state, NULL, 0, CHECKSUM_LEN);
    crypto_generichash_update(&state, public_key, BIN_256);
    crypto_generichash_final( &state, check, sizeof(check));

    // Copy in the prefix and shift pointer
    strcpy(address_buf, CONFIG_NL_ADDRESS_PREFIX);
    address_buf += strlen(ADDRESS_PREFIX);

    // Helper macro to create a virtual array of check and public_key variables
    #define accGetByte(x) (uint8_t)( \
        ((x) < 5) ? check[(x)] : \
        ((x) - 5 < 32) ? public_key[32 - 1 - ((x) - 5)] : \
        0 \
    )
    for (k = 0; k < ADDRESS_DATA_LEN; k++) {
        i = (k / 8) * 5;
        c = 0;
        switch (k % 8) {
        case 0:
            c = accGetByte(i) & B_11111;
            break;
        case 1:
            c = (accGetByte(i) >> 5) & B_00111;
            c |= (accGetByte(i + 1) & B_00011) << 3;
            break;
        case 2:
            c = (accGetByte(i + 1) >> 2) & B_11111;
            break;
        case 3:
            c = (accGetByte(i + 1) >> 7) & B_00001;
            c |= (accGetByte(i + 2) & B_01111) << 1;
            break;
        case 4:
            c = (accGetByte(i + 2) >> 4) & B_01111;
            c |= (accGetByte(i + 3) & B_00001) << 4;
            break;
        case 5:
            c = (accGetByte(i + 3) >> 1) & B_11111;
            break;
        case 6:
            c = (accGetByte(i + 3) >> 6) & B_00011;
            c |= (accGetByte(i + 4) & B_00111) << 2;
            break;
        case 7:
            c = (accGetByte(i + 4) >> 3) & B_11111;
            break;
        }
        address_buf[ADDRESS_DATA_LEN-1-k] = BASE32_ALPHABET[c];
    }
    #undef accGetByte
    
    address_buf[ADDRESS_DATA_LEN] = '\0';
}

