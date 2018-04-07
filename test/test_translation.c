#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include "sodium.h"

#include "nano_lib.h"
#include "helpers.h"


TEST_CASE("Public Address To Public Key", "[nano_lib]"){
    uint256_t guess_public_key_bin;
    hex256_t guess_public_key_hex;
    nl_err_t res;

    /* Test 1 - Standard Case (xrb_ prefix)*/
    res = nl_address_to_public(guess_public_key_bin,
            "xrb_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9");
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
        "nl_address_to_public returned an unsuccessful code");

    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strupper(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            guess_public_key_hex);

    /* Test 2 - No Prefix*/
    res = nl_address_to_public(guess_public_key_bin,
            "1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9");
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
        "nl_address_to_public returned an unsuccessful code");
    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strupper(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            guess_public_key_hex);

    /* Test 3 - nano_ prefix*/
    res = nl_address_to_public(guess_public_key_bin,
            "nAnO_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9");
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
        "nl_address_to_public returned an unsuccessful code");
    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strupper(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            guess_public_key_hex);

    /* Test 4 - Incomplete address*/
    res = nl_address_to_public(guess_public_key_bin,
            "nAnO_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm");
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_INVALID_ADDRESS, res,
        "nl_address_to_public didn't return E_INVALID_ADDRESS for a too short "
        "address.");
}

TEST_CASE("Public Key To Public Address", "[nano_lib]"){
    char guess_address[ADDRESS_BUF_LEN];
    char short_buffer[10];
    uint256_t test_public_key_bin;
    nl_err_t res;

    /* Test 1 - Normal Use*/
    sodium_hex2bin(test_public_key_bin, sizeof(test_public_key_bin), \
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            HEX_256, NULL, NULL, NULL);
    res = nl_public_to_address(guess_address,
            sizeof(guess_address),
            test_public_key_bin);
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
        "nl_public_to_address returned an unsuccessful code");
    TEST_ASSERT_EQUAL_STRING(
            "xrb_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9",
            guess_address);

    /* Test 1 - Insufficient buffer to hold address*/
    sodium_hex2bin(test_public_key_bin, sizeof(test_public_key_bin), \
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            HEX_256, NULL, NULL, NULL);
    res = nl_public_to_address(short_buffer,
            sizeof(short_buffer),
            test_public_key_bin);
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_INSUFFICIENT_BUF, res,
            "nl_public_to_address didn't return insufficient buffer error "
            "for a too short buffer.");
}

