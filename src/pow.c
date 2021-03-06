/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include "sodium.h"
#include "sodium/private/common.h"
#include "freertos/FreeRTOS.h"
#include "hash_wrapper.h"

#include "nano_lib.h"

//static uint64_t const publish_test_threshold = 0xff00000000000000;
static uint64_t const publish_full_threshold = 0xffffffc000000000;

jolt_err_t nl_parse_server_work_string(hex64_t work_str, uint64_t *work_int){
    /* Converts an ascii hex string to a uint64_t and flips the endianness.
     * This allows work to be used in local computations.
     *
     * Returns 0 on error */
    if( sodium_hex2bin((uint8_t *)work_int, sizeof(uint64_t),
            work_str, sizeof(hex64_t),
            NULL, NULL, NULL) ){
        return E_FAILURE;
    }
    *work_int = __bswap_64(*work_int);
    return E_SUCCESS;
}

void nl_generate_server_work_string(hex64_t work, uint64_t nonce){
    /* Inverse of nl_parse_server_work_string()*/
    nonce = __bswap_64(nonce);
    sodium_bin2hex(work, HEX_64, (uint8_t *)&nonce, sizeof(nonce));
}

static uint64_t pow_output (uint256_t hash, uint64_t nonce){
    /* Computes the resulting hash of using nonce. For Nano's PoW, you want the
     * output hash to be high
     */
    uint64_t res;
    nl_hash_ctx_t state;
    nl_hash_init(&state, sizeof(res));
    nl_hash_update(&state, (uint8_t *)&nonce, sizeof(nonce));
    nl_hash_update(&state, hash, BIN_256);
    nl_hash_final(&state, (uint8_t *)&res, sizeof(res));
    return res;
}

bool nl_pow_verify(uint256_t hash, uint64_t nonce){
    return pow_output (hash, nonce) >= publish_full_threshold;
}

uint64_t nl_compute_local_pow(uint256_t hash, uint64_t nonce){
    for(; !nl_pow_verify(hash, nonce); nonce++);
    return nonce;
}

