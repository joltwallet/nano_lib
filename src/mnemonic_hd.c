#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"

#include "nano_lib.h"
#include "helpers.h"
#include "bip39_en.h"

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
     * Buf will contain a space separated mnemonic list according to 
     * strength*/
    if(strength % 32 || strength < 128 || strength > 256){
        return E_INVALID_STRENGTH;
    }

    // Generate Checksum
    uint8_t entropy_len = strength / 8;
	uint8_t m_len = entropy_len * 3 / 4; //number of mnemonic words
    CONFIDENTIAL unsigned char checksummed_entropy[sizeof(uint256_t) + 1];

	if(buf_len < (m_len * 10 + 1)){
		return E_INSUFFICIENT_BUF;
	}

    // Make checksummed entropy first entropy_len bits be entropy, remaining
    // bits (up to 8 needed) be the first bits from the sha256 hash
    crypto_hash_sha256(checksummed_entropy, entropy, entropy_len);
    checksummed_entropy[entropy_len] = checksummed_entropy[0];
    memcpy(checksummed_entropy, entropy, entropy_len);
    

    #define BITS_PER_WORD 11
	CONFIDENTIAL uint16_t list_idx;
    uint8_t i, j;
    uint16_t bit_idx;
	for (i = 0; i < m_len; i++, buf++) {
		for (j=0, list_idx=0, bit_idx = i * BITS_PER_WORD;
                j < BITS_PER_WORD;
                j++, bit_idx++) {
            list_idx <<=1;
			list_idx += ( checksummed_entropy[bit_idx / 8] & 
		                  (1 << (7 - bit_idx % 8))
                        ) > 0;
		}
        // Copy the word over from the mnemonic word list
		strcpy(buf, wordlist[list_idx]);
		buf += strlen(wordlist[list_idx]);
		buf[0] = (i < m_len - 1) ? ' ' : 0;
	}
    #undef BITS_PER_WORD
    sodium_memzero(&list_idx, sizeof(list_idx));
	sodium_memzero(checksummed_entropy, sizeof(checksummed_entropy));

	return E_SUCCESS;
}
