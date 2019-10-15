/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"
#include "hash_wrapper.h"
#include "sdkconfig.h"

#include "nano_lib.h"
#include "jolttypes.h"

#if CONFIG_NANO_LIB_SIGNATURE_INTERNAL
/* Modified orlp/ed25519 implementation */
#include "ge.h"
#include "sc.h"
#else
/* libsodium implementation */
#include "sodium/private/curve25519_ref10.h"
#endif

void nl_private_to_public(uint256_t pk, const uint256_t sk) {  
    ge_p3 A;
    
    uint512_t hash;
    nl_hash_ctx_t state;
    nl_hash_init(&state, BIN_512);
    nl_hash_update(&state, sk, BIN_256);
    nl_hash_final(&state, hash, BIN_512);  

    hash[0] &= 248;
    hash[31] &= 63;
    hash[31] |= 64;
  
    ge_scalarmult_base(&A, hash);
    ge_p3_tobytes(pk, &A);
}

void nl_seed_to_private(uint256_t priv_key, const uint256_t seed_bin,
        uint32_t index){
    // Derives the private key from seed at index
    nl_hash_ctx_t state;

    index = __bswap_32(index);

    nl_hash_init(&state, BIN_256);
    nl_hash_update(&state, seed_bin, BIN_256);
    nl_hash_update(&state, (uint8_t *)&index, sizeof(index));
    nl_hash_final(&state, priv_key, BIN_256);

    sodium_memzero(&state, sizeof(state));
}

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
    nl_hash_ctx_t hs;
    CONFIDENTIAL unsigned char az[64];
    unsigned char nonce[64];
    unsigned char hram[64];
    ge_p3 R;

    // Generate 64 bytes (512 bits) from private key into az
    nl_hash_init(&hs, 64);
    nl_hash_update(&hs, sk, 32);
    nl_hash_final(&hs, az, 64);

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    nl_hash_init(&hs, 64);
    nl_hash_update(&hs, az + 32, 32);
    nl_hash_update(&hs, m, mlen);
    nl_hash_final(&hs, nonce, 64);

    memmove(sig + 32, pk, 32); // set upper 32 bits of sig

    sc_reduce(nonce);
    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(sig, &R);

    nl_hash_init(&hs, 64);
    nl_hash_update(&hs, sig, 64);
    nl_hash_update(&hs, m, mlen);
    nl_hash_final(&hs, hram, 64);

    sc_reduce(hram);
    sc_muladd(sig + 32, hram, az, nonce);

    sodium_memzero(az, sizeof az);
}

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
    nl_hash_ctx_t hs;
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
    nl_hash_init(&hs, 64);
    nl_hash_update(&hs, sig, 32);
    nl_hash_update(&hs, pk, 32);
    nl_hash_update(&hs, m, mlen);
    nl_hash_final(&hs, h, 64);

    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge_tobytes(rcheck, &R);

    return crypto_verify_32(rcheck, sig) | (-(rcheck == sig)) |
           sodium_memcmp(sig, rcheck, 32);
}
