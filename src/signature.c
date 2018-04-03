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
    
    unsigned char hash[BIN_512];
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
