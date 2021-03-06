/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"
#include "mbedtls/bignum.h"
#include "hash_wrapper.h"

#include "nano_lib.h"
#include "jolttypes.h"

#ifdef ESP_PLATFORM
#include "esp_log.h"
static const char *TAG = "nano_lib_block";
#endif

static void hash_state (const nl_block_t *block, uint256_t digest);
static void hash_open (const nl_block_t *block, uint256_t digest);
static void hash_change (const nl_block_t *block, uint256_t digest);
static void hash_send (const nl_block_t *block, uint256_t digest);
static void hash_receive (const nl_block_t *block, uint256_t digest);

static uint256_t STATE_BLOCK_PREAMBLE = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6};

void nl_block_init(nl_block_t *block){
    /* Initializes a block with all values set to 0 */
    block->type = UNDEFINED;
    sodium_memzero(block->account, sizeof(block->account));
    sodium_memzero(block->previous, sizeof(block->previous));
    sodium_memzero(block->representative, sizeof(block->representative));
    sodium_memzero(&(block->work), sizeof(block->work));
    sodium_memzero(block->signature, sizeof(block->signature));
    sodium_memzero(block->link, sizeof(block->link));

    mbedtls_mpi_init(&(block->balance));
    mbedtls_mpi_lset(&(block->balance), 0);
}

void nl_block_free(nl_block_t *block){
    mbedtls_mpi_free(&(block->balance));
}

void nl_block_copy(nl_block_t *dst, nl_block_t *src){
    /* Copies contents from block src to block dst */
    memcpy( &(dst->type), &(src->type), sizeof(nl_block_type_t) );
    memcpy( dst->account, src->account, sizeof(uint256_t) );
    memcpy( dst->previous, src->previous, sizeof(uint256_t) );
    memcpy( dst->representative, src->representative, sizeof(uint256_t) );
    dst->work = src->work;
    memcpy( &(dst->signature), src->signature, sizeof(uint512_t) );
    memcpy( dst->link, src->link, sizeof(uint256_t) );
    mbedtls_mpi_copy(&(*dst).balance, &(*src).balance);
}

bool nl_block_equal(nl_block_t *dst, nl_block_t *src){
    /* Tests to see if the blocks are equivalent */
    if( memcmp( &(dst->type), &(src->type), sizeof(nl_block_type_t) ) ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Type.");
        #endif
        return false;
    }
    if( memcmp( dst->account, src->account, sizeof(uint256_t) ) ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Account.");
        #endif
        return false;
    }
    if( memcmp( dst->previous, src->previous, sizeof(uint256_t) ) ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Previous.");
        #endif
        return false;
    }
    if( memcmp( dst->representative, src->representative, sizeof(uint256_t) ) ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Representative.");
        #endif
        return false;
    }
    if( dst->work != src->work ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Work.");
        #endif
        return false;
    }
    if( memcmp( &(dst->signature), src->signature, sizeof(uint512_t) ) ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Signature.");
        #endif
        return false;
    }
    if( memcmp( dst->link, src->link, sizeof(uint256_t) ) ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Link.");
        #endif
        return false;
    }

    if( 0 != mbedtls_mpi_cmp_mpi(&((*dst).balance), &((*src).balance)) ) {
        #ifdef ESP_PLATFORM
        ESP_LOGI(TAG, "Block Comparison Fail: Different Balance.");
        #endif
        return false;
    }
    return true;
}

jolt_err_t nl_block_sign(nl_block_t *block,
        const uint256_t private_key){
    /* Fills in the signature field of a block given a 256-bit private key and
     * the content of the other fields. The "account" field will be overwritten
     * with the freshly rederived public key to prevent leaks*/

    nl_private_to_public(block->account, private_key);

    uint256_t digest;
    jolt_err_t res;

    res = nl_block_compute_hash(block, digest);
    if(res){
        return res;
    }
    nl_sign_detached(block->signature,
            digest, sizeof(digest),
            private_key, block->account);
    return E_SUCCESS;
}

static void hash_state (const nl_block_t *block, uint256_t digest){
    nl_hash_ctx_t state;
    uint128_t balance;

    mbedtls_mpi_write_binary(&(block->balance), balance, sizeof(balance));

    nl_hash_init(&state, BIN_256);
    nl_hash_update(&state, STATE_BLOCK_PREAMBLE, sizeof(STATE_BLOCK_PREAMBLE));
    nl_hash_update(&state, block->account, sizeof(block->account));
    nl_hash_update(&state, block->previous, sizeof(block->previous));
    nl_hash_update(&state, block->representative, sizeof(block->representative));
    nl_hash_update(&state, balance, sizeof(balance));
    nl_hash_update(&state, block->link, sizeof(block->link));
    nl_hash_final(&state, digest, BIN_256);
}

static void hash_open (const nl_block_t *block, uint256_t digest){
    nl_hash_ctx_t state;

    nl_hash_init(&state, BIN_256);
    nl_hash_update(&state, block->link, sizeof(block->link));
    nl_hash_update(&state, block->representative, sizeof(block->representative));
    nl_hash_update(&state, block->account, sizeof(block->account));
    nl_hash_final(&state, digest, BIN_256);
}

static void hash_change (const nl_block_t *block, uint256_t digest){
    nl_hash_ctx_t state;

    nl_hash_init(&state, BIN_256);
    nl_hash_update(&state, block->previous, sizeof(block->previous));
    nl_hash_update(&state, block->representative, sizeof(block->representative));
    nl_hash_final(&state, digest, BIN_256);
}

static void hash_send (const nl_block_t *block, uint256_t digest){
    uint128_t balance;
    nl_hash_ctx_t state;

    mbedtls_mpi_write_binary(&(block->balance), balance, sizeof(balance));

    nl_hash_init(&state, BIN_256);
    nl_hash_update(&state, block->previous, sizeof(block->previous));
    nl_hash_update(&state, block->link, sizeof(block->link));
    nl_hash_update(&state, balance, sizeof(balance));
    nl_hash_final(&state, digest, BIN_256);
}

static void hash_receive (const nl_block_t *block, uint256_t digest){
    nl_hash_ctx_t state;

    nl_hash_init(&state, BIN_256);
    nl_hash_update(&state, block->previous, sizeof(block->previous));
    nl_hash_update(&state, block->link, sizeof(block->link));
    nl_hash_final(&state, digest, BIN_256);
}

jolt_err_t nl_block_compute_hash(const nl_block_t *block, uint256_t hash){
    switch(block->type){
        case UNDEFINED:
            return E_UNDEFINED_BLOCK_TYPE;
        case STATE:
            hash_state(block, hash);
            break;
        case OPEN:
            hash_open(block, hash);
            break;
        case CHANGE:
            hash_change(block, hash);
            break;
        case SEND:
            hash_send(block, hash);
            break;
        case RECEIVE:
            hash_receive(block, hash);
            break;
        default:
            return E_UNDEFINED_BLOCK_TYPE;
    }
    return E_SUCCESS;
}

