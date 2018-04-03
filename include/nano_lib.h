#ifndef __NANO_LIB_H__
#define __NANO_LIB_H__

/* Structs (and Struct Prototypes)*/
typedef struct{} block_t;

typedef enum nl_err_t{
    E_SUCCESS=0,
    E_FAILURE,
    E_INSUFFICIENT_BUF,
    E_INVALID_ADDRESS
} nl_err_t;

/* Generic Definitions */
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

/* Useful Extra values */
#define BURN_ADDRESS "xrb_1111111111111111111111111111111111111111111111111111hifc8npp"

/* typedefs */
typedef unsigned char uint128_t[BIN_128];
typedef char hex128_t[HEX_128];

typedef unsigned char uint256_t[BIN_256];
typedef char hex256_t[HEX_256];

typedef unsigned char uint512_t[BIN_512];
typedef char hex512_t[HEX_512];

/* Lookup Tables */
static const char BASE32_ALPHABET[] = {
        '1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
        'r', 's', 't', 'u', 'w', 'x', 'y', 'z' };

static const uint8_t BASE32_TABLE[] = {
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

//void raisecurity_sign_block(block_t *block);
//void raisecurity_sign_digest(char[32]);
#endif
