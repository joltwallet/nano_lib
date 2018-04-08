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

    /* Test 1 */
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

    /* Test 2 */
    res = nl_mnemonic_to_master_seed(guess_master_seed_bin, 
            "hamster diagram private dutch cause delay private meat slide "
            "toddler razor book happy fancy gospel tennis maple dilemma "
            "loan word shrug inflict delay length",
            "TREZOR");
    sodium_bin2hex(guess_master_seed_hex, sizeof(guess_master_seed_hex),
            guess_master_seed_bin, sizeof(guess_master_seed_bin));
    sodium_memzero(guess_master_seed_bin, sizeof(guess_master_seed_bin));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_mnemonic_to_master_seed returned an unsuccessful code");
    TEST_ASSERT_EQUAL_STRING(
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d2"
            "0b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
            guess_master_seed_hex);
    sodium_memzero(guess_master_seed_hex, sizeof(guess_master_seed_hex));

}

TEST_CASE("Mnemonic to Nano Seed", "[nano_lib]"){
    /* Use's Roosmaa's BIP39 Demo as reference for test case 
     * https://github.com/roosmaa/nano-bip39-demo */
    // "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur" -password "some password" -path "44'/165'/0'"
    // Private key: 3be4fc2ef3f3b7374e6fc4fb6e7bb153f8a2998b3b3dab50853eabe128024143
    // Public key: 5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4
    // Nano address: nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d
    //
    CONFIDENTIAL uint512_t guess_master_seed_bin;
    CONFIDENTIAL hex512_t guess_master_seed_hex;

    CONFIDENTIAL uint256_t guess_nano_seed_bin;
    CONFIDENTIAL hex256_t guess_nano_seed_hex;

    CONFIDENTIAL uint256_t guess_private_key_bin;
    CONFIDENTIAL hex256_t guess_private_key_hex;

    CONFIDENTIAL uint256_t guess_public_key_bin;
    CONFIDENTIAL hex256_t guess_public_key_hex;

    CONFIDENTIAL char guess_address[ADDRESS_BUF_LEN];

    nl_mnemonic_to_master_seed(guess_master_seed_bin, 
            "edge defense waste choose enrich upon flee junk siren film clown "
            "finish luggage leader kid quick brick print evidence swap drill "
            "paddle truly occur",
            "some password");
    sodium_bin2hex(guess_master_seed_hex, sizeof(guess_master_seed_hex),
            guess_master_seed_bin, sizeof(guess_master_seed_bin));
    TEST_ASSERT_EQUAL_STRING(
            "0dc285fde768f7ff29b66ce7252d56ed92fe003b605907f7a4f683c3dc8586d3"
            "4a914d3c71fc099bb38ee4a59e5b081a3497b7a323e90cc68f67b5837690310c",
            guess_master_seed_hex);


    nl_master_seed_to_nano_seed(guess_nano_seed_bin, guess_master_seed_bin);
    sodium_bin2hex(guess_nano_seed_hex, sizeof(guess_nano_seed_hex),
            guess_nano_seed_bin, sizeof(guess_nano_seed_bin));
    strlower(guess_nano_seed_hex);
    TEST_ASSERT_EQUAL_STRING( // private key according to roosmaa
            "3be4fc2ef3f3b7374e6fc4fb6e7bb153f8a2998b3b3dab50853eabe128024143",
            guess_nano_seed_hex);
    
    nl_private_to_public(guess_public_key_bin, guess_nano_seed_bin); 
    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strlower(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4",
            guess_public_key_hex);

    nl_public_to_address(guess_address, sizeof(guess_address),
            guess_public_key_bin);
    strlower(guess_address);
    TEST_ASSERT_EQUAL_STRING(
            "xrb_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d",
            guess_address);

}

