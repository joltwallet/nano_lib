/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"
#include "mbedtls/bignum.h"

#include "nano_lib.h"
#include "helpers.h"

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
    memcpy( dst, src, sizeof(nl_block_t) - sizeof(mbedtls_mpi) );
    mbedtls_mpi_copy(&(*dst).balance, &(*src).balance);
}

bool nl_block_equal(nl_block_t *dst, nl_block_t *src){
    /* Tests to see if the blocks are equivalent */
    if( 0 != memcmp(dst, src, sizeof(nl_block_t) - sizeof(mbedtls_mpi)) ){
        return false;
    }
    if( 0 != mbedtls_mpi_cmp_mpi(&((*dst).balance), &((*src).balance)) ) {
        return false;
    }
    return true;
}

nl_err_t nl_block_sign(nl_block_t *block,
        const uint256_t private_key){
    /* Fills in the signature field of a block given a 256-bit private key and
     * the content of the other fields. The "account" field will be overwritten
     * with the freshly rederived public key to prevent leaks*/

    nl_private_to_public(block->account, private_key);

    uint256_t digest;
    nl_err_t res;

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
    crypto_generichash_final(&state, digest, BIN_256);
}

static void hash_open (const nl_block_t *block, uint256_t digest){
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, BIN_256, BIN_256);
    crypto_generichash_update(&state, block->link, sizeof(block->link));
    crypto_generichash_update(&state, block->representative, sizeof(block->representative));
    crypto_generichash_update(&state, block->account, sizeof(block->account));
    crypto_generichash_final(&state, digest, BIN_256);
}

static void hash_change (const nl_block_t *block, uint256_t digest){
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, BIN_256, BIN_256);
    crypto_generichash_update(&state, block->previous, sizeof(block->previous));
    crypto_generichash_update(&state, block->representative, sizeof(block->representative));
    crypto_generichash_final(&state, digest, BIN_256);
}

static void hash_send (const nl_block_t *block, uint256_t digest){
    uint128_t balance;
    crypto_generichash_state state;

    mbedtls_mpi_write_binary(&(block->balance), balance, sizeof(balance));

    crypto_generichash_init(&state, NULL, BIN_256, BIN_256);
    crypto_generichash_update(&state, block->previous, sizeof(block->previous));
    crypto_generichash_update(&state, block->link, sizeof(block->link));
    crypto_generichash_update(&state, balance, sizeof(balance));
    crypto_generichash_final(&state, digest, BIN_256);
}

static void hash_receive (const nl_block_t *block, uint256_t digest){
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, BIN_256, BIN_256);
    crypto_generichash_update(&state, block->previous, sizeof(block->previous));
    crypto_generichash_update(&state, block->link, sizeof(block->link));
    crypto_generichash_final(&state, digest, BIN_256);
}

nl_err_t nl_block_compute_hash(const nl_block_t *block, uint256_t hash){
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

