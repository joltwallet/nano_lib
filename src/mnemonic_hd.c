#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "freertos/FreeRTOS.h"

#include "nano_lib.h"
#include "helpers.h"
#include "bip39_en.h"

#define BITS_PER_WORD 11

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
    sodium_memzero(&list_idx, sizeof(list_idx));
	sodium_memzero(checksummed_entropy, sizeof(checksummed_entropy));

	return E_SUCCESS;
}

int16_t nl_search_wordlist(char *word, uint8_t word_len){
    /* Returns the index of the word that starts with parameter word.
     * Returns -1 if word is not found
     */
    uint8_t i_letter;
    uint16_t index = (1<<(BITS_PER_WORD-1)) - 1;

    strnlower(word, word_len);

    // Minimalistic Binary search for [0,2046]
    for(uint16_t depth=(1<<(BITS_PER_WORD-1)); depth>0;){
        depth>>=1;
        for(i_letter=0; i_letter < word_len; i_letter++){
            if(word[i_letter] > wordlist[index][i_letter]){
                index += depth;
            }
            else if(word[i_letter] < wordlist[index][i_letter]){
                index -= depth;
            }
            else{
                if(i_letter == word_len-1){
                    return index;
                }
                continue;
            }
            break;
        }
    }
    // Check if it's zoo
    if(strncmp(word, wordlist[2047], word_len)==0){
        return 2047;
    }

    return -1;
}

nl_err_t nl_mnemonic_to_entropy(uint256_t entropy, const char mnemonic[],
        const uint8_t mnemonic_buf_len){
    /* mnemonic should be null terminated
     *
     */
    uint8_t m_len;
    uint16_t i_word, i_letter;
    char *current_word;
    uint8_t current_word_len; // not including \0

    // Get number of words in mnemonic
    for(i_letter=0, m_len=0;
            mnemonic[i_letter] || i_letter < mnemonic_buf_len;
            i_letter++){
        if(mnemonic[i_letter] == ' '){
            m_len++;
        }
    }
    if (m_len!=12 && m_len!=18 && m_len!=24){
        return E_INVALID_MNEMONIC_LEN;
    }

    // Iterate through words
    for(i_word=0, i_letter=0, current_word=mnemonic;
            i_word < m_len; i_word++){
        // Find the length of the current word
        for(current_word_len=0;
                mnemonic[i_letter]!=' ' && i_letter<mnemonic_buf_len;
                i_letter++){
            current_word_len++;
        }
    }
    return E_SUCCESS;
}
