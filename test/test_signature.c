#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include "sodium.h"

#include "nano_lib.h"
#include "helpers.h"


TEST_CASE("Verify Signature", "[nano_lib]"){
    uint256_t test_public_key_bin;
    uint512_t test_sig_bin;
    const char test_message[] = "Block-Lattice";
    nl_err_t res;

    /* Test 1 */
    sodium_hex2bin(test_public_key_bin, sizeof(test_public_key_bin), \
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(test_sig_bin, sizeof(test_sig_bin), \
            "6B0FCF86D2B04CB1919F25C76AE45C411D59F6F10768918FE6DC8F13DBB81BD2"
            "94AF6057B635105DB8F5EA3FC612256B12EDABB548379076F4A07E8ACAAF8F05",
            HEX_512, NULL, NULL, NULL);

	res = nl_verify_sig_detached(test_sig_bin,
        	(uint8_t *)test_message, strlen(test_message),
			test_public_key_bin);

    TEST_ASSERT_EQUAL_MESSAGE(E_SUCCESS, res, "Rejected Valid Signature");

    /* Test 2 */
    sodium_hex2bin(test_public_key_bin, sizeof(test_public_key_bin), \
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(test_sig_bin, sizeof(test_sig_bin), \
            "6B0FCF86D2B04CB1919F25C76AE45C411D59F6F10768918FE6DC8F13DBB81BD2"
            "94AF6057B635105DB8F5EA3FC612256B12EDABB548379076F4A07E8ACAAF8F06",
            HEX_512, NULL, NULL, NULL);

	res = nl_verify_sig_detached(test_sig_bin,
        	(uint8_t *)test_message, strlen(test_message),
			test_public_key_bin);

    TEST_ASSERT_EQUAL_MESSAGE(E_FAILURE, -res, "Accepted Invalid Signature");
}

TEST_CASE("Private Key To Public Key", "[nano_lib]"){
    uint256_t test_private_key_bin;
    uint256_t guess_public_key_bin;
    hex256_t guess_public_key_hex;

    /* Test Case 1 - Normal Use */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin), \
            "102A1BD8E50D314B1AF18B064763836500961D97E1517B409D9797E37F148290",
            HEX_256, NULL, NULL, NULL);
	nl_private_to_public(guess_public_key_bin, test_private_key_bin);
    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strupper(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            guess_public_key_hex);
}

TEST_CASE("Seed To Private Key", "[nano_lib]"){
    uint256_t test_seed_bin;
    CONFIDENTIAL uint256_t guess_private_key_bin;
    CONFIDENTIAL hex256_t guess_private_key_hex;

    sodium_hex2bin(test_seed_bin, sizeof(test_seed_bin), \
            "1A620665F60713F867D7D7F77BA337360B303C8C3C94E84819C4E282B6EAC262",
            HEX_256, NULL, NULL, NULL);

    /* Test Index 0 */
    nl_seed_to_private(guess_private_key_bin, test_seed_bin, 0);
    sodium_bin2hex(guess_private_key_hex, sizeof(guess_private_key_hex),
            guess_private_key_bin, sizeof(guess_private_key_bin));
    strupper(guess_private_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "102A1BD8E50D314B1AF18B064763836500961D97E1517B409D9797E37F148290",
            guess_private_key_hex);

    /* Test Index 1 */
    nl_seed_to_private(guess_private_key_bin, test_seed_bin, 1);
    sodium_bin2hex(guess_private_key_hex, sizeof(guess_private_key_hex),
            guess_private_key_bin, sizeof(guess_private_key_bin));
    strupper(guess_private_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            guess_private_key_hex);

    sodium_memzero(guess_private_key_bin, sizeof(guess_private_key_bin));
    sodium_memzero(guess_private_key_hex, sizeof(guess_private_key_hex));
}

TEST_CASE("Sign Message", "[nano_lib]"){
    uint512_t guess_sig_bin;
    hex512_t guess_sig_hex;
    uint256_t test_private_key_bin;
    uint256_t test_public_key_bin;
    const char test_message[] = "Block-Lattice";

    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin), \
            "102A1BD8E50D314B1AF18B064763836500961D97E1517B409D9797E37F148290",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(test_public_key_bin, sizeof(test_public_key_bin), \
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            HEX_256, NULL, NULL, NULL);

    nl_sign_detached(guess_sig_bin,
            (unsigned char *) test_message, strlen(test_message), 
            test_private_key_bin, test_public_key_bin);
    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            guess_sig_bin, sizeof(guess_sig_bin));
    strupper(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "6B0FCF86D2B04CB1919F25C76AE45C411D59F6F10768918FE6DC8F13DBB81BD2"
            "94AF6057B635105DB8F5EA3FC612256B12EDABB548379076F4A07E8ACAAF8F05",
            guess_sig_hex);
}

