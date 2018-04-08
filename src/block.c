#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"
#include "mbedtls/bignum.h"

#include "nano_lib.h"
#include "helpers.h"

static uint256_t STATE_BLOCK_PREAMBLE = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6};

nl_err_t nl_block_init(nl_block_t *block){
    block->type = UNDEFINED;
    sodium_memzero(block->account, sizeof(block->account));
    sodium_memzero(block->previous, sizeof(block->previous));
    sodium_memzero(block->representative, sizeof(block->representative));
    sodium_memzero(block->work, sizeof(block->work));
    sodium_memzero(block->signature, sizeof(block->signature));
    sodium_memzero(block->link, sizeof(block->link));
    mbedtls_mpi_init(&(block->balance));
    return E_SUCCESS;
}

nl_err_t nl_block_free(nl_block_t *block){
    mbedtls_mpi_free(&(block->balance));
    return E_SUCCESS;
}

static nl_err_t sign_open(nl_block_t *block, const uint256_t private_key){
    /*
     * link must contain the hash of the source block
     */
    uint256_t digest;
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, sizeof(digest), sizeof(digest));
    crypto_generichash_update(&state, block->link, sizeof(block->link));
    crypto_generichash_update(&state, block->representative, sizeof(block->representative));
    crypto_generichash_update(&state, block->account, sizeof(block->account));
    crypto_generichash_final(&state, digest, sizeof(digest));

    nl_sign_detached(block->signature,
            digest, sizeof(digest),
            private_key, block->account);
    return E_SUCCESS;
}

static nl_err_t sign_change(nl_block_t *block, const uint256_t private_key){
    /*
     */
    uint256_t digest;
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, sizeof(digest), sizeof(digest));
    crypto_generichash_update(&state, block->previous, sizeof(block->previous));
    crypto_generichash_update(&state, block->representative, sizeof(block->representative));
    crypto_generichash_final(&state, digest, sizeof(digest));

    nl_sign_detached(block->signature,
            digest, sizeof(digest),
            private_key, block->account);
    return E_SUCCESS;
}

static nl_err_t sign_receive(nl_block_t *block, const uint256_t private_key){
    uint256_t digest;
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, sizeof(digest), sizeof(digest));
    crypto_generichash_update(&state, block->previous, sizeof(block->previous));
    crypto_generichash_update(&state, block->link, sizeof(block->link));
    crypto_generichash_final(&state, digest, sizeof(digest));

    nl_sign_detached(block->signature,
            digest, sizeof(digest),
            private_key, block->account);
    return E_SUCCESS;
}

static nl_err_t sign_send(nl_block_t *block, const uint256_t private_key){
    uint256_t digest;
    uint128_t balance;
    crypto_generichash_state state;

    mbedtls_mpi_write_binary(&(block->balance), balance, sizeof(balance));

    crypto_generichash_init(&state, NULL, sizeof(digest), sizeof(digest));
    crypto_generichash_update(&state, block->previous, sizeof(block->previous));
    crypto_generichash_update(&state, block->link, sizeof(block->link));
    crypto_generichash_update(&state, balance, sizeof(balance));
    crypto_generichash_final(&state, digest, sizeof(digest));

    nl_sign_detached(block->signature,
            digest, sizeof(digest),
            private_key, block->account);
    return E_SUCCESS;
}

static nl_err_t sign_state(nl_block_t *block, const uint256_t private_key){
    uint256_t hash;
    nl_compute_block_hash(block, hash);

    nl_sign_detached(block->signature,
            hash, sizeof(hash),
            private_key, block->account);
    return E_SUCCESS;
}

nl_err_t nl_sign_block(nl_block_t *block,
        const uint256_t private_key){
    // Todo; test private key
    switch(block->type){
        case UNDEFINED:
            return E_UNDEFINED_BLOCK_TYPE;
        case STATE:
            return sign_state(block, private_key);
        case OPEN:
            return sign_open(block, private_key);
        case CHANGE:
            return sign_change(block, private_key);
        case SEND:
            return sign_send(block, private_key);
        case RECEIVE:
            return sign_receive(block, private_key);
        default:
            return E_UNDEFINED_BLOCK_TYPE;
    }
    return E_END_OF_FUNCTION;
}

void nl_compute_block_hash(const nl_block_t *block, uint256_t hash){
    crypto_generichash_state state;
    uint128_t balance;

    mbedtls_mpi_write_binary(&(block->balance), balance, sizeof(balance));

    crypto_generichash_init(&state, NULL, BIN_256, BIN_256);
    crypto_generichash_update(&state, STATE_BLOCK_PREAMBLE, sizeof(STATE_BLOCK_PREAMBLE));
    crypto_generichash_update(&state, block->account, sizeof(block->account));
    crypto_generichash_update(&state, block->previous, sizeof(block->previous));
    crypto_generichash_update(&state, block->representative, sizeof(block->representative));
    crypto_generichash_update(&state, balance, sizeof(balance));
    crypto_generichash_update(&state, block->link, sizeof(block->link));
    crypto_generichash_final(&state, hash, BIN_256);
}

