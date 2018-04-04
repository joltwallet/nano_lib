#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"

#include "sodium/private/curve25519_ref10.h"

#include "nano_lib.h"
#include "helpers.h"

// Derives Nano Public Key from Private Key
int nl_private_to_public(uint256_t pk, const uint256_t sk) {  
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

    return 0;
}

// Derive Nano Private Key From Seed and Index
void nl_seed_to_private(uint256_t priv_key, const uint256_t seed_bin,
        const uint32_t index){
    // Derives the private key from seed at index
    unsigned char index_array[4] = {0};
    int_to_char_array(index_array, index);

    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, BIN_256, BIN_256);
    crypto_generichash_update(&state, seed_bin, BIN_256);
    crypto_generichash_update(&state, index_array, sizeof(index_array));
    crypto_generichash_final(&state, priv_key, BIN_256);

    sodium_memzero(&state, sizeof(state));
}

// Sign some message m
int nl_sign_detached(uint512_t sig,
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
    unsigned char az[64];
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

    return 0;
}
