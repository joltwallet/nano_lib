/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#ifndef __NANO_LIB_H__
#define __NANO_LIB_H__

#include "mbedtls/bignum.h"
#include "jolttypes.h"

/* Structs (and Struct Prototypes)*/
typedef struct{} block_t;

/* Constant Buffer Lengths */
#define BALANCE_DEC_BUF_LEN 40
#define ADDRESS_BUF_LEN 70
#define ADDRESS_DATA_LEN 60 // Does NOT include null character
#define BLOCK_BUF_LEN 512 // todo: optimize this number

/* Useful Extra values */
#define BURN_ADDRESS "xrb_1111111111111111111111111111111111111111111111111111hifc8npp"

typedef enum nl_block_type_t{
    UNDEFINED=0, STATE, OPEN, CHANGE, SEND, RECEIVE
} nl_block_type_t;

typedef struct nl_block_t{
    nl_block_type_t type;
    uint256_t account;
    uint256_t previous;
    uint256_t representative;
    uint64_t work;
    uint512_t signature;
    uint256_t link;
    mbedtls_mpi balance;
} nl_block_t;

/* Lookup Tables */
static const char const BASE32_ALPHABET[] = {
        '1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
        'r', 's', 't', 'u', 'w', 'x', 'y', 'z' };

static const uint8_t const BASE32_TABLE[] = {
    0xff, 0x00, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0xff, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0xff, 0x1c,
    0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0xff, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0xff, 0x1c, 0x1d, 0x1e, 0x1f };

/* Function Prototypes */
jolt_err_t nl_public_to_address(char address_buf[], uint8_t address_buf_len, const uint256_t public_key);
jolt_err_t nl_address_to_public(uint256_t pub_key, const char address[]);
jolt_err_t nl_mpi_to_nano_double(mbedtls_mpi *amount_m, double *amount_d);

void nl_block_init(nl_block_t *block);
void nl_block_free(nl_block_t *block);
void nl_block_copy(nl_block_t *dst, nl_block_t *src);
bool nl_block_equal(nl_block_t *dst, nl_block_t *src);

void nl_generate_seed(uint256_t ent);

void nl_private_to_public(uint256_t pk, const uint256_t sk);
void nl_seed_to_private(uint256_t priv_key, const uint256_t seed_bin,
        uint32_t index);
void nl_sign_detached(uint512_t sig,
        const unsigned char m[], unsigned int mlen,
        const uint256_t sk, const uint256_t pk);
jolt_err_t nl_verify_sig_detached(const uint512_t sig,
        const unsigned char m[], unsigned int mlen,
        const uint256_t pk);


jolt_err_t nl_block_sign(nl_block_t *block, const uint256_t private_key);
jolt_err_t nl_block_compute_hash(const nl_block_t *block, uint256_t hash);

void nl_master_seed_to_nano_private_key(uint256_t private_key, 
        uint512_t master_seed, uint32_t index);

jolt_err_t nl_parse_server_work_string(hex64_t work_str, uint64_t *work_int);
void nl_generate_server_work_string(hex64_t work, const uint64_t nonce);
bool nl_pow_verify(uint256_t hash, uint64_t nonce);
uint64_t nl_compute_local_pow(uint256_t hash, uint64_t nonce);

#endif
