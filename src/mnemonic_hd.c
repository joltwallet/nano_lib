/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "sodium/private/common.h"
#include "freertos/FreeRTOS.h"

#include "nano_lib.h"
#include "helpers.h"
#include "bip39_en.h"

#define BITS_PER_WORD 11
#define HARDENED 0x80000000

typedef struct hd_node_t {
    uint256_t key;
    uint256_t chain_code;
} hd_node_t;

#if 0
static void hd_node_copy(hd_node_t *dst, const hd_node_t *src){
    memcpy(dst->key, src->key, sizeof(src->key));
    memcpy(dst->chain_code, src->chain_code, sizeof(src->chain_code));
}
#endif

static void hd_node_init(hd_node_t *node, const uint512_t master_seed, 
        const char *key){
    /* key - null-terminated string. Typically "ed25519 seed" or "Bitcoin Seed" */
    CONFIDENTIAL uint512_t digest;
    CONFIDENTIAL crypto_auth_hmacsha512_state state;

    crypto_auth_hmacsha512_init(&state, (uint8_t *)key, strlen(key));
    crypto_auth_hmacsha512_update(&state, master_seed, BIN_512);
    crypto_auth_hmacsha512_final(&state, digest);

    memcpy(node->key, digest, 32);
    memcpy(node->chain_code, digest + 32, 32);

    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&state, sizeof(state));
}

static void hd_node_iterate_hardened(hd_node_t *node, uint32_t val){
    /* Overwrites node values according to val */
    CONFIDENTIAL uint512_t digest;
    CONFIDENTIAL crypto_auth_hmacsha512_state state;
    unsigned char data[1+32+4] = {0};

    val |= HARDENED;
    val = bswap_32(val);

    memcpy(data+1, node->key, sizeof(node->key));
    memcpy(data+1+32, &val, sizeof(val) );

    crypto_auth_hmacsha512_init(&state, node->chain_code, sizeof(node->chain_code));
    crypto_auth_hmacsha512_update(&state, data, sizeof(data));
    crypto_auth_hmacsha512_final(&state, digest);

    memcpy(node->key, digest, 32);
    memcpy(node->chain_code, digest + 32, 32);

    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&state, sizeof(state));
}

#define DERIVATION_PURPOSE 44
//#define BIP32_KEY "Bitcoin seed"
#define BIP32_KEY "ed25519 seed"

void nl_master_seed_to_nano_private_key(uint256_t private_key, 
        uint512_t master_seed, uint32_t index){
    CONFIDENTIAL hd_node_t node;
    hd_node_init(&node, master_seed, BIP32_KEY);
    // 44'
    hd_node_iterate_hardened(&node, DERIVATION_PURPOSE);
    // 44'/165'
    hd_node_iterate_hardened(&node, CONFIG_NANO_LIB_DERIVATION_PATH);
    // 44'/165'/0'
    hd_node_iterate_hardened(&node, index);

    memcpy(private_key, node.key, sizeof(node.key));
    sodium_memzero(&node, sizeof(node));
}

static void pbkdf2_hmac_sha512(const uint8_t *passwd, size_t passwdlen, 
        const uint8_t *salt, size_t saltlen,
        uint8_t *buf, size_t dkLen, uint64_t c){
    /*
     * c - number of iterations
     * buf - stores the derived key 
     * dkLen - derived key length in bits
     *
     * Based on the pbkdf2 sha256 code in libsodium
     */
    CONFIDENTIAL crypto_auth_hmacsha512_state PShctx;
    crypto_auth_hmacsha512_state hctx;
    size_t                       i;
    uint8_t                      ivec[4];
    CONFIDENTIAL uint8_t         U[crypto_auth_hmacsha512_BYTES];
    CONFIDENTIAL uint8_t         T[crypto_auth_hmacsha512_BYTES];
    uint64_t                     j;
    int                          k;
    size_t                       clen;

    crypto_auth_hmacsha512_init(&PShctx, passwd, passwdlen);
    crypto_auth_hmacsha512_update(&PShctx, salt, saltlen);

    for (i = 0; i * crypto_auth_hmacsha512_BYTES < dkLen; i++) {
        STORE32_BE(ivec, (uint32_t)(i + 1));
        memcpy(&hctx, &PShctx, sizeof(crypto_auth_hmacsha512_state));
        crypto_auth_hmacsha512_update(&hctx, ivec, sizeof(ivec));
        crypto_auth_hmacsha512_final(&hctx, U);

        memcpy(T, U, sizeof(T));
        /* LCOV_EXCL_START */
        for (j = 2; j <= c; j++) {
            crypto_auth_hmacsha512_init(&hctx, passwd, passwdlen);
            crypto_auth_hmacsha512_update(&hctx, U, sizeof(U));
            crypto_auth_hmacsha512_final(&hctx, U);

            for (k = 0; k < sizeof(U); k++) {
                T[k] ^= U[k];
            }
        }
        /* LCOV_EXCL_STOP */

        clen = dkLen - i * 64;
        if (clen > crypto_auth_hmacsha512_BYTES) {
            clen = crypto_auth_hmacsha512_BYTES;
        }
        memcpy(&buf[i * crypto_auth_hmacsha512_BYTES], T, clen);
    }
    sodium_memzero((void *) &PShctx, sizeof PShctx);
    sodium_memzero(U, sizeof(U));
    sodium_memzero(T, sizeof(T));
}

nl_err_t nl_mnemonic_generate(char buf[], uint16_t buf_len, uint16_t strength){
    /* Strength in bits */
    if(strength % 32 || strength < 128 || strength >256){
        return E_INVALID_STRENGTH;
    }
    nl_err_t res;
    CONFIDENTIAL uint256_t entropy;
    nl_generate_seed(entropy);
    res = nl_entropy_to_mnemonic(buf, buf_len, entropy, strength);
    sodium_memzero(entropy, sizeof(entropy));
    return res;
}

nl_err_t nl_entropy_to_mnemonic(char buf[], const uint16_t buf_len,
        const uint256_t entropy, const uint16_t strength){
    /* Strength in bits 
     * Sets Buf to a space separated mnemonic string with length according to 
     * strength. This mnemonic string is derived from the 256-bit entropy. */
    if(strength % 32 || strength < 128 || strength > 256){
        return E_INVALID_STRENGTH;
    }

    /* Generate Checksum */
    uint8_t entropy_len = strength / 8;
    uint8_t m_len = entropy_len * 3 / 4; //number of mnemonic words
    CONFIDENTIAL unsigned char cs_entropy[sizeof(uint256_t) + 1];

    if(buf_len < (m_len * 10 + 1)){
        return E_INSUFFICIENT_BUF;
    }

    // Make cs_entropy first entropy_len bits be entropy, remaining
    // bits (up to 8 needed) be the first bits from the sha256 hash
    crypto_hash_sha256(cs_entropy, entropy, entropy_len);
    cs_entropy[entropy_len] = cs_entropy[0];
    memcpy(cs_entropy, entropy, entropy_len);

    CONFIDENTIAL uint16_t list_idx;
    uint8_t i, j;
    uint16_t bit_idx;
    for (i = 0; i < m_len; i++, buf++) {
        for (j=0, list_idx=0, bit_idx = i * BITS_PER_WORD;
                j < BITS_PER_WORD;
                j++, bit_idx++) {
            list_idx <<=1;
            list_idx += ( cs_entropy[bit_idx / 8] & 
                          (1 << (7 - bit_idx % 8))
                        ) > 0;
        }
        // Copy the word over from the mnemonic word list
        strcpy(buf, wordlist[list_idx]);
        buf += strlen(wordlist[list_idx]);
        buf[0] = (i < m_len - 1) ? ' ' : 0;
    }
    sodium_memzero(&list_idx, sizeof(list_idx));
    sodium_memzero(cs_entropy, sizeof(cs_entropy));

    return E_SUCCESS;
}

int16_t nl_search_wordlist(char *word, uint8_t word_len){
    /* Performs binary search on the wordlist
     *
     * Returns the index of the word that starts with parameter word.
     * Returns -1 if word is not found
     */
    uint16_t index = (1<<(BITS_PER_WORD-1)) - 1;

    if( NULL == word || 0 == word_len ){
        return -1;
    }

    strnlower(word, word_len);

    // Minimalistic Binary search for [0,2046]
    for(uint16_t depth=(1<<(BITS_PER_WORD-1)); depth>0;){
        depth>>=1;

        int res = strncmp(word, wordlist[index], word_len);
        if(res>0){
            index += depth;
        }
        else if(res < 0){
            index -= depth;
        }
        else if( strlen(wordlist[index]) == word_len ){
            return index;
        }
        else{
            return -1;
        }
    }
    // Check if it's zoo (index 2047)
    if(strncmp(word, wordlist[2047], word_len)==0){
        return 2047;
    }

    return -1;
}

static uint8_t get_word_len(char **start, const char *str){
    /* gets the length of a word and pointer to where it starts 
     * ignores whitespace, newlines, and tabs*/
    bool state = false;
    uint8_t cc = 0;
    *start = NULL;
    for(; *str; str++){
        if (*str != ' ' && *str != '\n' && *str != '\t'){
            if(!state){
                *start = (char *) str;
            }
            state = true;
            cc++;
        }
        else if (state){
            return cc;
        }
    }
    return cc;
}

static uint8_t get_word_count(const char *str){
    /* counts the number of words separated by possibly multiple spaces,
     * newlines, and tabs. */
    uint8_t wc = 0;  // word count
    char *start;
    uint8_t cc;
    while((cc = get_word_len(&start, str))>0 ){
        wc++;
        str = start + cc;
    }
    return wc;
}

nl_err_t nl_verify_mnemonic(const char mnemonic[]){
    /* Expects a null-terminated mnemonic string.
     * The mnemonic can have arbitrary whitespace leading, trailing, and
     * between workds
     */
    int8_t j;
    uint8_t m_len, i_word, current_word_len;
    int16_t bit_idx, mnemonic_index;
    char *current_word, *start;
    CONFIDENTIAL unsigned char cs_entropy[sizeof(uint256_t) + 1] = {0};

    // Check number of words in mnemonic
    m_len = get_word_count(mnemonic);
    if (m_len!=12 && m_len!=18 && m_len!=24){
        return E_INVALID_MNEMONIC_LEN;
    }

    // Iterate through words in user's mnemonic
    for(i_word=0, bit_idx=0, current_word=(char *)mnemonic;
            i_word < m_len;
            i_word++, current_word+=current_word_len){
        current_word_len = get_word_len(&start, current_word);
        current_word = start;
        mnemonic_index = nl_search_wordlist(current_word, current_word_len);
        if(mnemonic_index == -1){
            return E_INVALID_MNEMONIC;
        }
        for(j=BITS_PER_WORD-1; j>=0; j--, bit_idx++){
            if(mnemonic_index & (1 << j)){
                cs_entropy[bit_idx/8] |= 1 << (7 - (bit_idx % 8)) ;
            }
        }
    }

    // Verify Checksum
    cs_entropy[32] = cs_entropy[m_len * 4/3];
    crypto_hash_sha256(cs_entropy, cs_entropy, m_len * 4/3);
    if (m_len == 12 && (cs_entropy[0] & 0xF0) == (cs_entropy[32] & 0xF0) ) {
        return E_SUCCESS;
    }
    else if (m_len == 18 && (cs_entropy[0] & 0xFC) == (cs_entropy[32] & 0xFC)) {
        return E_SUCCESS;
    }
    else if (m_len == 24 && cs_entropy[0] == cs_entropy[32]) {
        return E_SUCCESS;
    }

    return E_INVALID_CHECKSUM;
}

nl_err_t nl_mnemonic_to_master_seed(uint512_t master_seed, 
        const char mnemonic[], const char passphrase[]){
    /* mnemonic must be a null terminated string.
     * passphrase must be a null terminated string. Up to PASSPHRASE_BUF_LEN bytes
     * It is recommended to verify the mnemonic before calling this function.
     */
    /* Filter the input mnemonic */
    CONFIDENTIAL char salt[8+PASSPHRASE_BUF_LEN+1];
    CONFIDENTIAL char clean_mnemonic[MNEMONIC_BUF_LEN];
    uint8_t m_len;
    uint8_t word_len;
    char *word_ptr;
    char *m_ptr;

    if(strlen(passphrase) > PASSPHRASE_BUF_LEN){
        return E_INSUFFICIENT_BUF;
    }

    m_len = get_word_count(mnemonic);
    if (m_len!=12 && m_len!=18 && m_len!=24){
        return E_INVALID_MNEMONIC_LEN;
    }

    /* Filter out extra whitespace in mnemonic*/
    m_ptr = clean_mnemonic;
    for(uint8_t i=0; i<m_len; i++, m_ptr++){
        word_len = get_word_len(&word_ptr, mnemonic);
        mnemonic = word_ptr + word_len;
        memcpy(m_ptr, word_ptr, word_len);
        m_ptr += word_len;
        *m_ptr = ' ';
    }
    *(m_ptr-1) = '\0';

    memcpy(salt, "mnemonic", 8);
    strcpy(salt + 8, passphrase);
    pbkdf2_hmac_sha512(
            (uint8_t *) clean_mnemonic, strlen(clean_mnemonic), 
            (uint8_t *) salt, strlen(salt),
            (uint8_t *) master_seed, sizeof(uint512_t),
            2048);
    sodium_memzero(salt, strlen(salt));
    sodium_memzero(clean_mnemonic, strlen(clean_mnemonic));
    return E_SUCCESS;
}
