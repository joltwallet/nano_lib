#ifndef __NANO_LIB_H__
#define __NANO_LIB_H__

#include "mbedtls/bignum.h"

/* Structs (and Struct Prototypes)*/
typedef struct{} block_t;

/* Errors Nano Lib functions can return */
typedef enum nl_err_t{
    E_SUCCESS=0,
    E_FAILURE,
    E_NOT_IMPLEMENTED,
    E_END_OF_FUNCTION,
    E_INSUFFICIENT_BUF,
    E_INVALID_ADDRESS,
    E_UNDEFINED_BLOCK_TYPE,
    E_INVALID_STRENGTH,
    E_INVALID_MNEMONIC,
    E_INVALID_MNEMONIC_LEN,
    E_INVALID_CHECKSUM,
    E_UNABLE_ALLOCATE_MEM,
} nl_err_t;

/* Generic Definitions */
#define CONFIDENTIAL // Way to mark sensitive data
#define NUM_OF(x) (sizeof (x) / sizeof (*x))

#define BIN_64 8
#define BIN_128 16
#define BIN_256 32
#define BIN_512 64

#define HEX_64 (2*BIN_64+1)
#define HEX_128 (2*BIN_128+1)
#define HEX_256 (2*BIN_256+1)
#define HEX_512 (2*BIN_512+1)

/* Constant Buffer Lengths */
#define ADDRESS_BUF_LEN 70
#define BLOCK_BUF_LEN 512 // todo: optimize this number
#define MNEMONIC_BUF_LEN (24 * 10 + 1)

/* Useful Extra values */
#define BURN_ADDRESS "xrb_1111111111111111111111111111111111111111111111111111hifc8npp"

/* typedefs */
// Todo: make bin/uint uniform
typedef unsigned char bin64_t[BIN_64];
typedef char hex64_t[HEX_64];

typedef unsigned char uint128_t[BIN_128];
typedef char hex128_t[HEX_128];

typedef unsigned char uint256_t[BIN_256];
typedef char hex256_t[HEX_256];

typedef unsigned char uint512_t[BIN_512];
typedef char hex512_t[HEX_512];

typedef enum nl_block_type_t{
    UNDEFINED=0, STATE, OPEN, CHANGE, SEND, RECEIVE
} nl_block_type_t;

typedef struct nl_block_t{
    nl_block_type_t type;
    uint256_t account;
    uint256_t previous;
    uint256_t representative;
    bin64_t work;
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
nl_err_t nl_public_to_address(char address_buf[], uint8_t address_buf_len, const uint256_t public_key);
nl_err_t nl_address_to_public(uint256_t pub_key, const char address[]);

nl_err_t nl_block_init(nl_block_t *block);
nl_err_t nl_block_free(nl_block_t *block);

void nl_private_to_public(uint256_t pk, const uint256_t sk);
void nl_seed_to_private(uint256_t priv_key, const uint256_t seed_bin,
        const uint32_t index);
void nl_sign_detached(uint512_t sig,
        const unsigned char m[], unsigned int mlen,
        const uint256_t sk, const uint256_t pk);

nl_err_t nl_sign_block(nl_block_t *block, const uint256_t private_key);


int16_t nl_search_wordlist(char *word, uint8_t word_len);
nl_err_t nl_mnemonic_generate(char buf[], uint16_t buf_len, uint16_t strength);
nl_err_t nl_entropy_to_mnemonic(char buf[], const uint16_t buf_len,
        const uint256_t entropy, const uint16_t strength);
nl_err_t nl_verify_mnemonic(const char mnemonic[]);
nl_err_t nl_mnemonic_to_master_seed(uint512_t master_seed, 
        const char mnemonic[], const char passphrase[]);


#endif
