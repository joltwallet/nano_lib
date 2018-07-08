/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"

#include "sodium/private/curve25519_ref10.h"

#include "nano_lib.h"
#include "jolttypes.h"
#include "helpers.h"

// Derives Nano Public Key from Private Key
void nl_private_to_public(uint256_t pk, const uint256_t sk) {  
    ge_p3 A;
    
    uint512_t hash;
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, NULL, 0, BIN_512);
    crypto_generichash_blake2b_update(&state, sk, BIN_256);
    crypto_generichash_blake2b_final(&state, hash, BIN_512);  

    hash[0] &= 248;
    hash[31] &= 63;
    hash[31] |= 64;
  
    ge_scalarmult_base(&A, hash);
    ge_p3_tobytes(pk, &A);
}

// Derive Nano Private Key From Seed and Index
void nl_seed_to_private(uint256_t priv_key, const uint256_t seed_bin,
        uint32_t index){
    // Derives the private key from seed at index
    crypto_generichash_state state;

    index = bswap_32(index);

    crypto_generichash_init(&state, NULL, BIN_256, BIN_256);
    crypto_generichash_update(&state, seed_bin, BIN_256);
    crypto_generichash_update(&state, (uint8_t *)&index, sizeof(index));
    crypto_generichash_final(&state, priv_key, BIN_256);

    sodium_memzero(&state, sizeof(state));
}

// Sign some message m
void nl_sign_detached(uint512_t sig,
        const unsigned char m[], unsigned int mlen,
        const uint256_t sk, const uint256_t pk){
    /* sig - Returned signature
     * siglen_p - Returned signature length (can be NULL if user doesn't care)
     * m - message to sign
     * mlen - length of message in bytes
     * sk - Secret Key
     * pk - Public Key
    */
    crypto_generichash_blake2b_state hs;
    CONFIDENTIAL unsigned char az[64];
    unsigned char nonce[64];
    unsigned char hram[64];
    ge_p3 R;

    // Generate 64 bytes (512 bits) from private key into az
    crypto_generichash_blake2b_init(&hs, NULL, 0, 64);
    crypto_generichash_blake2b_update(&hs, sk, 32);
    crypto_generichash_blake2b_final(&hs, az, 64);

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    crypto_generichash_blake2b_init(&hs, NULL, 0, 64);
    crypto_generichash_blake2b_update(&hs, az + 32, 32);
    crypto_generichash_blake2b_update(&hs, m, mlen);
    crypto_generichash_blake2b_final(&hs, nonce, 64);

    memmove(sig + 32, pk, 32); // set upper 32 bits of sig

    sc_reduce(nonce);
    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(sig, &R);

    crypto_generichash_blake2b_init(&hs, NULL, 0, 64);
    crypto_generichash_blake2b_update(&hs, sig, 64);
    crypto_generichash_blake2b_update(&hs, m, mlen);
    crypto_generichash_blake2b_final(&hs, hram, 64);

    sc_reduce(hram);
    sc_muladd(sig + 32, hram, az, nonce);

    sodium_memzero(az, sizeof az);
}

// Verify some message m
jolt_err_t nl_verify_sig_detached(const uint512_t sig,
        const unsigned char m[], unsigned int mlen,
        const uint256_t pk){
    /* sig - Returned signature
     * siglen_p - Returned signature length (can be NULL if user doesn't care)
     * m - message to sign
     * mlen - length of message in bytes
     * sk - Secret Key
     * pk - Public Key
    */
    crypto_generichash_blake2b_state hs;
    unsigned char            h[64];
    unsigned char            rcheck[32];
    unsigned int             i;
    unsigned char            d = 0;
    ge_p3                    A;
    ge_p2                    R;

    if (sig[63] & 224) {
        return E_FAILURE;
    }

    if (ge_frombytes_negate_vartime(&A, pk) != 0) {
        return E_FAILURE;
    }
    for (i = 0; i < 32; ++i) {
        d |= pk[i];
    }
    if (d == 0) {
        return E_FAILURE;
    }

    // Generate 64 bytes (512 bits) from private key into az
    crypto_generichash_blake2b_init(&hs, NULL, 0, 64);
    crypto_generichash_blake2b_update(&hs, sig, 32);
    crypto_generichash_blake2b_update(&hs, pk, 32);
    crypto_generichash_blake2b_update(&hs, m, mlen);
    crypto_generichash_blake2b_final(&hs, h, 64);

    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge_tobytes(rcheck, &R);

    return crypto_verify_32(rcheck, sig) | (-(rcheck == sig)) |
           sodium_memcmp(sig, rcheck, 32);
}
