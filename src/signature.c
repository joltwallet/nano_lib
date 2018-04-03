#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"

#include "sodium/private/curve25519_ref10.h"

#include "nano_lib.h"

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
