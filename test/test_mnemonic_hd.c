#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include "sodium.h"

#include "nano_lib.h"
#include "helpers.h"

/* Some test vectors were sourced from:
 * https://github.com/trezor/python-mnemonic/blob/master/vectors.json */


TEST_CASE("BIP39/44 Wordlist Search", "[nano_lib]"){
    char word[10];
    int16_t guess_index;

    strcpy(word, "abandon");
    guess_index = nl_search_wordlist(word, strlen(word));
    TEST_ASSERT_EQUAL_INT16(0, guess_index);

    strcpy(word, "zoo");
    guess_index = nl_search_wordlist(word, strlen(word));
    TEST_ASSERT_EQUAL_INT16(2047, guess_index);

    strcpy(word, "banana");
    guess_index = nl_search_wordlist(word, strlen(word));
    TEST_ASSERT_EQUAL_INT16(145, guess_index);

    strcpy(word, "meow");
    guess_index = nl_search_wordlist(word, strlen(word));
    TEST_ASSERT_EQUAL_INT16(-1, guess_index);

    strcpy(word, "zoo1");
    guess_index = nl_search_wordlist(word, strlen(word));
    TEST_ASSERT_EQUAL_INT16(-1, guess_index);

    strcpy(word, "1zoo");
    guess_index = nl_search_wordlist(word, strlen(word));
    TEST_ASSERT_EQUAL_INT16(-1, guess_index);
}

TEST_CASE("BIP39/44 Verify Mnemonic", "[nano_lib]"){
    nl_err_t res;

    res = nl_verify_mnemonic(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about"
            );
    TEST_ASSERT_EQUAL_INT(E_SUCCESS, res);

    res = nl_verify_mnemonic(
            "  legal winner thank year wave sausage worth useful legal winner "
            "thank yellow  "
            );
    TEST_ASSERT_EQUAL_INT(E_SUCCESS, res);

    res = nl_verify_mnemonic(
            "panda \neyebrow bullet gorilla call smoke muffin taste mesh "
            "discover    soft ostrich alcohol speed nation flash devote level "
            "hobby quick\t inner drive ghost inside"
            );
    TEST_ASSERT_EQUAL_INT(E_SUCCESS, res);

    res = nl_verify_mnemonic(
            "panda eyebrow  bullet gorilla call smoke muffin taste mesh "
            "discover soft ostrich alcohol speed\n nation flash devote level "
            "hobby quick inner drive ghost ghost "
            );
    TEST_ASSERT_EQUAL_INT(E_INVALID_CHECKSUM, res);
}

TEST_CASE("BIP39/44 Entropy to Mnemonic", "[nano_lib]"){
    CONFIDENTIAL uint256_t entropy;
    CONFIDENTIAL char buf[MNEMONIC_BUF_LEN];
    nl_err_t res;

    /* Test 1 */
    sodium_hex2bin(entropy, sizeof(entropy), \
            "00000000000000000000000000000000",
            HEX_256, NULL, NULL, NULL);
    res = nl_entropy_to_mnemonic(buf, sizeof(buf), entropy, 128);
    sodium_memzero(entropy, sizeof(entropy));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_entropy_to_mnemonic returned an unsuccessful code");
    TEST_ASSERT_EQUAL_STRING("abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about",
            buf);
    sodium_memzero(buf, sizeof(buf));

    /* Test 2 */
    sodium_hex2bin(entropy, sizeof(entropy), \
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            HEX_256, NULL, NULL, NULL);
    res = nl_entropy_to_mnemonic(buf, sizeof(buf), entropy, 128);
    sodium_memzero(entropy, sizeof(entropy));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_entropy_to_mnemonic returned an unsuccessful code");
    TEST_ASSERT_EQUAL_STRING(
            "legal winner thank year wave sausage worth useful legal winner "
            "thank yellow",
            buf);
    sodium_memzero(buf, sizeof(buf));

    /* Test 3 */
    sodium_hex2bin(entropy, sizeof(entropy), \
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            HEX_256, NULL, NULL, NULL);
    res = nl_entropy_to_mnemonic(buf, sizeof(buf), entropy, 256);
    sodium_memzero(entropy, sizeof(entropy));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_entropy_to_mnemonic returned an unsuccessful code");
    TEST_ASSERT_EQUAL_STRING(
            "panda eyebrow bullet gorilla call smoke muffin taste mesh "
            "discover soft ostrich alcohol speed nation flash devote level "
            "hobby quick inner drive ghost inside",
            buf);
    sodium_memzero(buf, sizeof(buf));

    /* Test 4 */
    sodium_hex2bin(entropy, sizeof(entropy), 
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            HEX_256, NULL, NULL, NULL);
    res = nl_entropy_to_mnemonic(buf, sizeof(buf), entropy, 256);
    sodium_memzero(entropy, sizeof(entropy));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_entropy_to_mnemonic returned an unsuccessful code");
    TEST_ASSERT_EQUAL_STRING(
            "void come effort suffer camp survey warrior heavy shoot primary "
            "clutch crush open amazing screen patrol group space point ten "
            "exist slush involve unfold",
            buf);
    sodium_memzero(buf, sizeof(buf));

    /* Test 5 */
    sodium_hex2bin(entropy, sizeof(entropy), 
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            HEX_256, NULL, NULL, NULL);
    res = nl_entropy_to_mnemonic(buf, 100, entropy, 256);
    sodium_memzero(entropy, sizeof(entropy));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_INSUFFICIENT_BUF, res,
        "nl_entropy_to_mnemonic didn't return insufficient buffer error");
    sodium_memzero(buf, sizeof(buf));
}

TEST_CASE("BIP39/44 Mnemonic To Master Seed", "[nano_lib]"){
    CONFIDENTIAL uint512_t guess_master_seed_bin;
    CONFIDENTIAL hex512_t guess_master_seed_hex;
    nl_err_t res;
    res = nl_mnemonic_to_master_seed(guess_master_seed_bin, 
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "TREZOR");
    sodium_bin2hex(guess_master_seed_hex, sizeof(guess_master_seed_hex),
            guess_master_seed_bin, sizeof(guess_master_seed_bin));
    sodium_memzero(guess_master_seed_bin, sizeof(guess_master_seed_bin));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_mnemonic_to_master_seed returned an unsuccessful code");
    TEST_ASSERT_EQUAL_STRING(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            guess_master_seed_hex);
    sodium_memzero(guess_master_seed_hex, sizeof(guess_master_seed_hex));
}

TEST_CASE("Nano Seed From Mnemonic", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
    /* Use's Roosmaa's BIP39 Demo as reference for test case 
     * https://github.com/roosmaa/nano-bip39-demo */
    // "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur" -password "some password" -path "44'/165'/0'"
    // Private key: 3be4fc2ef3f3b7374e6fc4fb6e7bb153f8a2998b3b3dab50853eabe128024143
    // Public key: 5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4
    // Nano address: nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d
    //

    /* Test 1 - Make Sure Bitcoin Derivation Works */


    /* Test 2 - Nano Derivation */
}

