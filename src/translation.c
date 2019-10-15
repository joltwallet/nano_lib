/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "hash_wrapper.h"

#include "nano_lib.h"
#include "jolttypes.h"

#define CHECKSUM_LEN 5
#define B_11111 31
#define B_01111 15
#define B_00111  7
#define B_00011  3
#define B_00001  1

static const char *TAG = "nl_translation";

const char BASE32_ALPHABET[] = {
        '1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
        'r', 's', 't', 'u', 'w', 'x', 'y', 'z' };

const uint8_t BASE32_TABLE[] = {
    0xff, 0x00, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0xff, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0xff, 0x1c,
    0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0xff, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0xff, 0x1c, 0x1d, 0x1e, 0x1f };

jolt_err_t nl_public_to_address(char address_buf[], const uint8_t address_buf_len,
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

    nl_hash_ctx_t state;

    // sizeof includes the null character required
    if (address_buf_len < (sizeof(CONFIG_NANO_LIB_ADDRESS_PREFIX) + ADDRESS_DATA_LEN)){
        return E_INSUFFICIENT_BUF;
    }

    // Compute the checksum
    nl_hash_init( &state, CHECKSUM_LEN);
    nl_hash_update( &state, public_key, BIN_256);
    nl_hash_final( &state, check, sizeof(check));

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

jolt_err_t nl_address_to_public(uint256_t pub_key, const char address[]){
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
    }
    if (size != ADDRESS_DATA_LEN){
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
    nl_hash_ctx_t state;
    nl_hash_init(&state, CHECKSUM_LEN);
    nl_hash_update(&state, pub_key, BIN_256);
    nl_hash_final(&state, check, CHECKSUM_LEN);

    for (i = 0; i < sizeof(check); i++) {
        if (check[i] != checkInp[i]) {
            return E_INVALID_ADDRESS;
        }
    }

    return E_SUCCESS;
}

jolt_err_t nl_mpi_to_nano_fixed_str(mbedtls_mpi *amount_m, char *buf_out, uint8_t buf_out_len){
    /* Produces string with 41 characters:
     *     * 39 digits
     *     * 1 decimal point
     *     * 1 null-termination
     * Output is left-padded with zeros; decimal is at 0-index position 9.
     * The returned value is the absolute value
     */
    char buf[66];
    size_t olen;

    if(buf_out_len <= 40){ // not enough buffer space
        return E_FAILURE;
    }

    if( 0 !=  mbedtls_mpi_write_string(amount_m, 10, buf, sizeof(buf), &olen)){
        ESP_LOGE(TAG, "Needed buffer of size %d.", olen);
        return E_FAILURE;
    }

    if(strlen(buf) > 39){ // max supply has 39 digits
        return E_FAILURE;
    }


    // insert decimal point
    // 39 char for max value, 1 char for null termination, 1 char for decimal point
    for(int8_t i=40, j=strlen(buf); i>=0; i--){
        if( i == 9){
            buf_out[i] = '.';
        }
        else if(j>=0){
            // on first pass this copies the null-termination
            if(buf[j] == '-'){
                buf_out[i] = '0';
            }
            else{
                buf_out[i] = buf[j];
            }
            j--;
        }
        else{
            buf_out[i] = '0';
        }
    }
    return E_SUCCESS;
}

#if 0
// todo: finish this up
jolt_err_t nl_mpi_to_nano_round_str(mbedtls_mpi *amount_m, char *buf_out, uint8_t buf_out_len, uint8_t n_dec){
    /* Removes uneccessary leading zeros, guarenteed accurate rounds to n_dec */
    char buf[41];
    if( E_SUCCESS != nl_mpi_to_nano_fixed_str(amount_m, buf, sizeof(buf))){
        return E_FAILURE;
    }

    if(n_dec > 30){
        n_dec = 30;
    }


    // perform rounding
    bool carry = buf[9 + n_dec + 1] >= '5';
    for(uint8_t i=9+n_dec; i>0 && carry;i--){
        if(buf[i]=='.'){
            continue;
        }

        if(buf[i]=='9'){
            buf[i]='0';
        }
        else{
            buf[i]++;
            break;
        }
    }
    
    //remove leading 0 padding
    bool first_nonzero = false;
    for(uint8_t i=0, j=0; i<9+n_dec; i++){
        if(!first_nonzero){
            if(buf[i] != '0'){
                if(11+n_dec - i > buf_out_len){
                    return E_INSUFFICIENT_BUFFER;
                }
                else if(buf[i] == '.'){
                    buf_out[j] = '0';
                    j++;
                    buf_out[j] = '.';
                    j++;
                }
                first_nonzero = true;
            }
        }
        else{
            buf_out[j] = buf[i];
            j++
        }
    }
    buf_out[9+n_dec] = '\0';
    return E_SUCCESS;
}
#endif

jolt_err_t nl_mpi_to_nano_double(mbedtls_mpi *amount_m, double *amount_d){
    char buf[41];
    if( E_SUCCESS != nl_mpi_to_nano_fixed_str(amount_m, buf, sizeof(buf))){
        return E_FAILURE;
    }
    sscanf(buf, "%lf", amount_d);
    // mbedtls_mpi.s is 1 for pos numbers, -1 for negative
    *amount_d *= amount_m->s;
    return E_SUCCESS;
}

