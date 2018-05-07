#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"

#include "nano_lib.h"

#define CHECKSUM_LEN 5
#define B_11111 31
#define B_01111 15
#define B_00111  7
#define B_00011  3
#define B_00001  1

nl_err_t nl_public_to_address(char address_buf[], const uint8_t address_buf_len,
        const uint256_t public_key){
    /* Translates a 256-bit binary public key into a NANO/XRB Address.
     *
     * address_buf will contain the resulting null terminated string
     *
     * This function does not contain sensitive data
     *
     * Based on Roosmaa's Ledger S Nano Github
     */
    uint8_t i, c;
    uint8_t check[CHECKSUM_LEN];

    crypto_generichash_state state;

    // sizeof includes the null character required
    if (address_buf_len < (sizeof(CONFIG_NANO_LIB_ADDRESS_PREFIX) + ADDRESS_DATA_LEN)){
        return E_INSUFFICIENT_BUF;
    }

    // Compute the checksum
    crypto_generichash_init( &state, NULL, 0, CHECKSUM_LEN);
    crypto_generichash_update( &state, public_key, BIN_256);
    crypto_generichash_final( &state, check, sizeof(check));

    // Copy in the prefix and shift pointer
    strlcpy(address_buf, CONFIG_NANO_LIB_ADDRESS_PREFIX, address_buf_len);
    address_buf += strlen(CONFIG_NANO_LIB_ADDRESS_PREFIX);

    // Helper macro to create a virtual array of check and public_key variables
    #define accGetByte(x) (uint8_t)( \
        ((x) < 5) ? check[(x)] : \
        ((x) - 5 < 32) ? public_key[32 - 1 - ((x) - 5)] : \
        0 \
    )
    for (int k = 0; k < ADDRESS_DATA_LEN; k++) {
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
    return E_SUCCESS;
}

nl_err_t nl_address_to_public(uint256_t pub_key, const char address[]){
	/* Translates an address to binary public key
     *
     * pub_key - 256-bit buffer to store the translated public key
     * address - Null terminated string containing address
     *
     * Based on Roosmaa's Ledger S Nano Github
	*/
    uint8_t i, c;
    uint8_t checkInp[CHECKSUM_LEN] = {0};
    uint8_t check[CHECKSUM_LEN] = {0};
	uint8_t size = strlen(address);

    // Check prefix and exclude it from the buffer
    if ((address[0] == 'n' || address[0] == 'N') &&
        (address[1] == 'a' || address[1] == 'A') &&
        (address[2] == 'n' || address[2] == 'N') &&
        (address[3] == 'o' || address[3] == 'O') &&
        (address[4] == '-' || address[4] == '_')) {
        if (size != ADDRESS_DATA_LEN + 5) {
            return E_INVALID_ADDRESS;
        }
        size -= 5;
        address += 5;
    } else if ((address[0] == 'x' || address[0] == 'X') &&
               (address[1] == 'r' || address[1] == 'R') &&
               (address[2] == 'b' || address[2] == 'B') &&
               (address[3] == '-' || address[3] == '_')) {
        if (size != ADDRESS_DATA_LEN + 4) {
            return E_INVALID_ADDRESS;
        }
        size -= 4;
        address += 4;
    } else if (size == ADDRESS_DATA_LEN){
        // continue; assumes address doesn't have a prefix
    } else {
        return E_INVALID_ADDRESS;
    }

    sodium_memzero(pub_key, sizeof(uint256_t));

    // Helper macro to create a virtual array of checkInp and outKey variables
    #define accPipeByte(x, v) \
        if ((x) < sizeof(checkInp)) { \
            checkInp[(x)] |= (v);\
        } else if ((x) - sizeof(checkInp) < 32) { \
            pub_key[32 - 1 - ((x) - sizeof(checkInp))] |= (v);\
        }
    for (int k = 0; k < size; k++) {
        i = (k / 8) * 5;

        c = address[size-1-k];
        if (c >= 0x30 && c < 0x30 + sizeof(BASE32_TABLE)) {
            c = BASE32_TABLE[c - 0x30];
        } else {
            c = 0;
        }

        switch (k % 8) {
            case 0:
                accPipeByte(i, c & B_11111);
                break;
            case 1:
                accPipeByte(i, (c & B_00111) << 5);
                accPipeByte(i + 1, (c >> 3) & B_00011);
                break;
            case 2:
                accPipeByte(i + 1, (c & B_11111) << 2);
                break;
            case 3:
                accPipeByte(i + 1, (c & B_00001) << 7);
                accPipeByte(i + 2, (c >> 1) & B_01111);
                break;
            case 4:
                accPipeByte(i + 2, (c & B_01111) << 4);
                accPipeByte(i + 3, (c >> 4) & B_00001);
                break;
            case 5:
                accPipeByte(i + 3, (c & B_11111) << 1);
                break;
            case 6:
                accPipeByte(i + 3, (c & B_00011) << 6);
                accPipeByte(i + 4, (c >> 2) & B_00111);
                break;
            case 7:
                accPipeByte(i + 4, (c & B_11111) << 3);
                break;
        }
    }
    #undef accPipeByte

    // Verify the checksum of the address
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, CHECKSUM_LEN);
    crypto_generichash_update(&state, pub_key, BIN_256);
    crypto_generichash_final(&state, check, CHECKSUM_LEN);

    for (i = 0; i < sizeof(check); i++) {
        if (check[i] != checkInp[i]) {
            return E_INVALID_ADDRESS;
        }
    }

    return E_SUCCESS;
}

