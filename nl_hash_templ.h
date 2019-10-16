#ifndef NANO_LIB_HASH_H__
#define NANO_LIB_HASH_H__

/*****
 * Copy this file to the parenting components directory to define a custom 
 * blake2b hashing implementation.
 */

#include "stddef.h"
#include "stdint.h"

/* Hashing context type */
typedef void nl_hash_ctx_t;

/**
 * @brief Initialize hashing context.
 * @param[in] ctx Outputs an initialized hashing context.
 * @param[in] hash_len Length of hash digest in bytes.
 * @return 0 on success.
 */
static inline int nl_hash_init(nl_hash_ctx_t *ctx, uint8_t hash_len)
{
    return -1;
}

/**
 * @brief Update hashing context.
 * @param[in] ctx Outputs an initialized hashing context.
 * @param[in] msg Message to hash
 * @param[in] msg_len Length of input msg in bytes.
 * @return 0 on success.
 */
static inline int nl_hash_update(nl_hash_ctx_t *ctx, const uint8_t *msg, size_t msg_len)
{
    return -1;
}

/**
 * @brief Finalize hashing context.
 * @param[in] ctx Outputs an initialized hashing context.
 * @param[out] hash Buffer to store the output digest. Must be same length as passed in nl_hash_init.
 * @param[out] hash_len Length of output hash buffer.
 * @return 0 on success.
 */
static inline int nl_hash_final(nl_hash_ctx_t *ctx, uint8_t *hash, uint8_t hash_len)
{
    return -1;
}

#endif
