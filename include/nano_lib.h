/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#ifndef __NANO_LIB_H__
#define __NANO_LIB_H__

#include <stdbool.h>
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

/**
 * @brief Converts a 256-bit public key to an ascii nano address.
 * @param[out] address_buf buffer to populate
 * @param[in] address_buf_len length of address_buf
 * @param[in] public_key Nano public key to convert into address
 * @return E_SUCCESS on success.
 */
jolt_err_t nl_public_to_address(char address_buf[], uint8_t address_buf_len, const uint256_t public_key);

/**
 * @brief Converts an ascii nano address into a 256-bit public key.
 * @param[out] pub_key 256-bit buffer to output public key
 * @param[in] address ascii nano address
 * @return E_SUCCESS on success.
 */
jolt_err_t nl_address_to_public(uint256_t pub_key, const char address[]);

/**
 * @brief Converts BigNum into a double for display purposes.
 *
 * DO NOT USE FOR BLOCK CONSTRUCTION OR AMOUNT VERIFICATION.
 *
 * Only to be used for approximate display.
 *
 * @param[in] amount_m input BigNum to convert to a double
 * @param[out] amound_d amount as a double
 * @return E_SUCCESS on success.
 */
jolt_err_t nl_mpi_to_nano_double(mbedtls_mpi *amount_m, double *amount_d);

/**
 * @brief Initialize block structure
 * @param[out] initialized Nano block
 */
void nl_block_init(nl_block_t *block);

/**
 * @brief De-allocate internal Nano block objects
 * @param[in] block to free
 */
void nl_block_free(nl_block_t *block);
/**
 * @brief copy the Nano block contents from src to dst
 * @param[out] dst must be initialized prior
 * @param[in] src source block top copy from
 */
void nl_block_copy(nl_block_t *dst, nl_block_t *src);

/**
 * @brief Checks if all fields match in values
 * @param[in] dst block to compare
 * @param[in] src block to compare
 * @return true if blocks contain equivalent content.
 */
bool nl_block_equal(nl_block_t *dst, nl_block_t *src);

/**
 * @brief Generates 256-bits of cryptographically secure entropy.
 *
 * Uses libsodium's randombytes
 *
 * @param[out] ent 256-bits of entropy
 */
void nl_generate_seed(uint256_t ent);

/**
 * @brief Derives the public key from the secret/private key using ed25519+blake2b
 * @param[out] pk derived public key
 * @param[in] sk input secret/private key
 */
void nl_private_to_public(uint256_t pk, const uint256_t sk);

/**
 * @brief Derives a private key from the seed using original nano derivation scheme.
 * @param[out] priv_key Derived private key
 * @param[in] seed_bin Master seed
 * @param[in] index Derivation index
 */
void nl_seed_to_private(uint256_t priv_key, const uint256_t seed_bin,
        uint32_t index);

/**
 * @brief Sign a message using ed25519+blake2b
 * @param[out] sig produced signature
 * @param[in] m message to sign
 * @param[in] mlen length of message
 * @param[in] sk secret/private key
 * @param[in] pk public key
 */
void nl_sign_detached(uint512_t sig,
        const unsigned char m[], unsigned int mlen,
        const uint256_t sk, const uint256_t pk);

/**
 * @brief Sign a message using ed25519+blake2b
 * @param[in] sig signature to verify
 * @param[in] m message that was signed
 * @param[in] mlen length of message
 * @param[in] pk public key
 * @return E_SUCCESS on successful verification
 */
jolt_err_t nl_verify_sig_detached(const uint512_t sig,
        const unsigned char m[], unsigned int mlen,
        const uint256_t pk);

/**
 * @brief sign a block
 *
 * Overwrites the "account" field with the public key derived from the private_key.
 *
 * @param[in,out] block Block to sign contents of. Populates the "signature" field.
 * @param[in] private_key private key to use
 */
jolt_err_t nl_block_sign(nl_block_t *block, const uint256_t private_key);

/**
 * @brief Computes the hash of a block
 *
 * @param[in] block Block to hash
 * @param[out] hash Resulting block hash
 * @return E_SUCCESS on success
 */
jolt_err_t nl_block_compute_hash(const nl_block_t *block, uint256_t hash);

/**
 * @brief Derivate private keys using BIP HD
 * @param[out] private_key Derived private key
 * @param[in] master_seed Root BIP master seed
 * @param[in] index Account index to derive
 */
void nl_master_seed_to_nano_private_key(uint256_t private_key, 
        uint512_t master_seed, uint32_t index);

/**
 * @brief Interprets a work string from a nano_node with the correct endianness
 * @param work_str[in] work_str ascii string buffer containing hex values
 * @param work_int[out] work_int output parsed nonce
 * @return E_SUCCESS on success
 */
jolt_err_t nl_parse_server_work_string(hex64_t work_str, uint64_t *work_int);

/**
 * @brief converts a local nonce to a string with correct endianness for remote nano_node server
 * @param[out] work ascii string buffer to populate with hex values
 * @param[in] nonce Local nonce value.
 */
void nl_generate_server_work_string(hex64_t work, const uint64_t nonce);

/**
 * @brief Verify if PoW is valid
 * @return True if the nonce is valid PoW
 */
bool nl_pow_verify(uint256_t hash, uint64_t nonce);

/**
 * @brief Computes PoW for a given hash
 *
 * This is a CPU intensive function that is generally not worth using on an
 * embedded device.
 *
 * Usually hash is the previous block hash. For open blocks its the public key.
 *
 * @param hash[in] hash Hash to compute PoW for
 * @param nonce[in] nonce Starting guess value. Doesn't really matter; best to start at 1 because a 0 nonce could be valid PoW, but is generally interpretted as an error value.
 * @return PoW nonce
 */
uint64_t nl_compute_local_pow(uint256_t hash, uint64_t nonce);

#endif
