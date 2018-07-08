#include "sodium.h"
#include "string.h"
#include "jolttypes.h"
#include "bipmnemonic.h"

void nl_generate_seed(uint256_t ent){
    /* Generates random 256-bits
     * Uses randombytes_random() from libsodium.
     * If libsodium is properly ported, this is a cryptographically secure
     * source.
     */
    CONFIDENTIAL uint32_t rand_buffer;

    for(uint8_t i=0; i<8; i++){
        rand_buffer = randombytes_random();
        memcpy(ent + 4*i, &rand_buffer, 4);
    }
    sodium_memzero(&rand_buffer, sizeof(rand_buffer));
}

void nl_master_seed_to_nano_private_key(uint256_t private_key, 
        uint512_t master_seed, uint32_t index) {
    bm_master_seed_to_private_key( private_key, master_seed,
            "ed25519 seed", 3, 44u | BM_HARDENED, 165u | BM_HARDENED, index | BM_HARDENED);
}

