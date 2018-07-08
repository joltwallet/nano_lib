/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include "sodium.h"

#include "jolttypes.h"
#include "bipmnemonic.h"
#include "nano_lib.h"

/* Some test vectors were sourced from:
 * https://github.com/trezor/python-mnemonic/blob/master/vectors.json */

TEST_CASE("Mnemonic to Nano (165) Private Key", "[bip_mnemonic]"){
    /* Use's Roosmaa's BIP39 Demo as reference for test case 
     * https://github.com/roosmaa/nano-bip39-demo */
    CONFIDENTIAL uint512_t guess_master_seed_bin;
    CONFIDENTIAL hex512_t guess_master_seed_hex;

    CONFIDENTIAL uint256_t guess_private_key_bin;
    CONFIDENTIAL hex256_t guess_private_key_hex;

    uint256_t guess_public_key_bin;
    hex256_t guess_public_key_hex;

    char guess_address[ADDRESS_BUF_LEN];

    /* Derive Master Seed */
    bm_mnemonic_to_master_seed(guess_master_seed_bin, 
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

    /* Derive Nano Private Key */
    bm_master_seed_to_private_key(guess_private_key_bin, guess_master_seed_bin,
            "ed25519 seed", 3, 44u | BM_HARDENED, 165u | BM_HARDENED, 0u | BM_HARDENED);

    sodium_bin2hex(guess_private_key_hex, sizeof(guess_private_key_hex),
            guess_private_key_bin, sizeof(guess_private_key_bin));
    TEST_ASSERT_EQUAL_STRING(
            "3be4fc2ef3f3b7374e6fc4fb6e7bb153f8a2998b3b3dab50853eabe128024143",
            guess_private_key_hex);
    
    /* Derive Nano Public Key */
    nl_private_to_public(guess_public_key_bin, guess_private_key_bin); 
    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strlwr(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4",
            guess_public_key_hex);

    /* Translate Public Key to Address */
    nl_public_to_address(guess_address, sizeof(guess_address),
            guess_public_key_bin);
    strlwr(guess_address);
    TEST_ASSERT_EQUAL_STRING(
            "xrb_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d",
            guess_address);

    sodium_memzero(guess_master_seed_bin, sizeof(guess_master_seed_bin));
    sodium_memzero(guess_master_seed_hex, sizeof(guess_master_seed_hex));
    sodium_memzero(guess_private_key_bin, sizeof(guess_private_key_bin));
    sodium_memzero(guess_private_key_hex, sizeof(guess_private_key_hex));
}

