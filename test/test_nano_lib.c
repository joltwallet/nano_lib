#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include "sodium.h"

#include "nano_lib.h"
#include "helpers.h"

TEST_CASE("Mneumonic to Index", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

TEST_CASE("Verify Mneumonic", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

TEST_CASE("Seed From Mneumonic", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

TEST_CASE("String Case Helpers", "[nano_lib]"){
    char buf[10];
    const char test_string[] = "NanO123$";

    strcpy(buf, test_string);
    strupper(buf);
    TEST_ASSERT_EQUAL_STRING("NANO123$", buf);

    strcpy(buf, test_string);
    strnupper(buf, 2);
    TEST_ASSERT_EQUAL_STRING("NAnO123$", buf);

    strcpy(buf, test_string);
    strlower(buf);
    TEST_ASSERT_EQUAL_STRING("nano123$", buf);

    strcpy(buf, test_string);
    strnlower(buf, 2);
    TEST_ASSERT_EQUAL_STRING("nanO123$", buf);
}

TEST_CASE("Generate Seed (256-bit entropy)", "[nano_lib]"){
    uint256_t seed_bin;
    hex256_t seed_hex;
    nl_generate_seed(seed_bin);
    sodium_bin2hex(seed_hex, sizeof(seed_hex),
            seed_bin, sizeof(seed_bin));
    strupper(seed_hex);
    printf("Generated Seed: %s\n", seed_hex);
}

TEST_CASE("Public Address To Public Key", "[nano_lib]"){
    uint256_t guess_public_key_bin;
    hex256_t guess_public_key_hex;
    nl_err_t res;

    /* Test 1 */
    res = nl_address_to_public(guess_public_key_bin,
            "xrb_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9");
    if(res != E_SUCCESS){
        TEST_FAIL_MESSAGE("nl_address_to_public returned an unsuccessful code");
    }

    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strupper(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            guess_public_key_hex);
}

TEST_CASE("Public Key To Public Address", "[nano_lib]"){
    char guess_address[ADDRESS_BUF_LEN];
    uint256_t test_public_key_bin;
    nl_err_t res;

    /* Test 1 */
    sodium_hex2bin(test_public_key_bin, sizeof(test_public_key_bin), \
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            HEX_256, NULL, NULL, NULL);
    res = nl_public_to_address(guess_address,
            sizeof(guess_address),
            test_public_key_bin);
    if(res != E_SUCCESS){
        TEST_FAIL_MESSAGE("nl_public_to_address returned an unsuccessful code");
    }
    TEST_ASSERT_EQUAL_STRING(
            "xrb_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9",
            guess_address);
}

TEST_CASE("Private Key To Public Key", "[nano_lib]"){
	int res;
    uint256_t test_private_key_bin;
    uint256_t guess_public_key_bin;
    hex256_t guess_public_key_hex;

    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin), \
            "102A1BD8E50D314B1AF18B064763836500961D97E1517B409D9797E37F148290",
            HEX_256, NULL, NULL, NULL);
	res = nl_private_to_public(guess_public_key_bin, test_private_key_bin);
    if(res != 0){
        TEST_FAIL_MESSAGE("nl_private_to_public returned an unsuccessful code");
    }
    sodium_bin2hex(guess_public_key_hex, sizeof(guess_public_key_hex),
            guess_public_key_bin, sizeof(guess_public_key_bin));
    strupper(guess_public_key_hex);
    TEST_ASSERT_EQUAL_STRING(
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31",
            guess_public_key_hex);
}

TEST_CASE("Seed To Private Key", "[nano_lib]"){
    uint256_t test_seed_bin;
    uint256_t guess_private_key_bin;
    hex256_t guess_private_key_hex;

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
}

TEST_CASE("Sign Message", "[nano_lib]"){
    // todo: verify the test case
    int res;
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

    res = nl_sign_detached(guess_sig_bin,
            (unsigned char *) test_message, strlen(test_message), 
            test_private_key_bin, test_public_key_bin);
    if(res != 0){
        TEST_FAIL_MESSAGE("nl_sign_detached returned an unsuccessful code");
    }
    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            guess_sig_bin, sizeof(guess_sig_bin));
    strupper(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "6B0FCF86D2B04CB1919F25C76AE45C411D59F6F10768918FE6DC8F13DBB81BD2"
            "94AF6057B635105DB8F5EA3FC612256B12EDABB548379076F4A07E8ACAAF8F05",
            guess_sig_hex);
}

TEST_CASE("Sign Send Block", "[nano_lib]"){
    nl_err_t res;
    hex512_t guess_sig_hex;
    uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    res = nl_block_init(&block);
    block.type = SEND;
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C",
            HEX_256, NULL, NULL, NULL);
    res = nl_address_to_public(block.link,
            "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8");
    sodium_hex2bin(block.work, sizeof(block.work),
            "f0f4d56c95d3e7e5", HEX_64, NULL, NULL, NULL);

    // Compute final account balance
    mbedtls_mpi transaction_amount;
    mbedtls_mpi_init(&transaction_amount);
    mbedtls_mpi_read_string(&transaction_amount, 10, "87593489348637673");

    // Original Amount
    mbedtls_mpi_read_string(&(block.balance), 10, "60051032083097114097032066");
    // Subtract Transaction Amount from the Original Amount
    mbedtls_mpi_sub_mpi(&(block.balance), &(block.balance), &transaction_amount);

    res = nl_sign_block(&block, test_private_key_bin);

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupper(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "A9807C7103BFD6D1A19E128F0D0318FAEF042E6A4497F7D53F17558043DB0225"
            "53B8B5259C0C317E771437A1790D613678F8EA954BE0B0157F16611C8195ED0B",
            guess_sig_hex);
    mbedtls_mpi_free(&transaction_amount);
    nl_block_free(&block);

    // Hash of this send block:
    // "hash": "6447171713541D387BAB4161E6BA40A88F41140218395DCCA0230BC29827717A"
}

TEST_CASE("Sign Receive Block", "[nano_lib]"){
    nl_err_t res;
    hex512_t guess_sig_hex;
    uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    res = nl_block_init(&block);
    block.type = RECEIVE;
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "AF9C1D46AAE66CC8F827904ED02D4B3D95AA98B1FF058352BA6B670BEFD40231",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.link, sizeof(block.link),
            "6447171713541D387BAB4161E6BA40A88F41140218395DCCA0230BC29827717A",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.work, sizeof(block.work),
            "f22c729331e5efb3", HEX_64, NULL, NULL, NULL);

    res = nl_sign_block(&block, test_private_key_bin);

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupper(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "C557AFF3388FA6372EC65D4A6C7256BFC2DCEE5E734C1B57B5791095A7910228"
            "9BBF5CE676D0A9451AB90314124A07653E9169AAABB82628BA57A1A3DD057A0E",
            guess_sig_hex);
    res = nl_block_free(&block);

    // Hash of this send block:
    // "hash": "AB67B959665FD6CE8B947196E8B0D00DE5D07FA38BE0938966530226D7F52446"
}

TEST_CASE("Sign Change Block", "[nano_lib]"){
    nl_err_t res;
    hex512_t guess_sig_hex;
    uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    res = nl_block_init(&block);
    block.type = CHANGE;
    res = nl_address_to_public(block.representative,
            "xrb_3dmtrrws3pocycmbqwawk6xs7446qxa36fcncush4s1pejk16ksbmakis78m");
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            HEX_256, NULL, NULL, NULL);

    sodium_hex2bin(block.work, sizeof(block.work), "3a74e84a07e6837c", HEX_64,
            NULL, NULL, NULL);

    res = nl_sign_block(&block, test_private_key_bin);

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupper(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "93E243440E64E44C7D33359F15B18EA3FC5E5A5B3EFB3996F1B05D436AF200E9"
            "1C6DBC16E0C62142776A0FAE393C85F43FAD16C5227225EA87E1FD08A46B4605",
            guess_sig_hex);
    res = nl_block_free(&block);

    // Hash of this send block:
    // "hash": "EFFACC9470702D3280FFDC22D1FA2922CB6BB85C86A4CEAAD6E68B63F607F3EC",
}

TEST_CASE("Sign Open Block", "[nano_lib]"){
    nl_err_t res;
    hex512_t guess_sig_hex;
    uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    res = nl_block_init(&block);
    block.type = OPEN;
    res = nl_address_to_public(block.representative,
            "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8");
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.work, sizeof(block.work), "d2183f1b5b08a7a8", HEX_64,
            NULL, NULL, NULL);
    sodium_hex2bin(block.link, sizeof(block.link),
            "BA5920AF3B105AB472DDD31100000F3952BA1BACCC4212874219064538BADFAA",
            HEX_256, NULL, NULL, NULL);

    res = nl_sign_block(&block, test_private_key_bin);

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupper(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "12776A6DBF21AD285EAA187EC9E7BDF622C18AAFE765100CA62FCD4C7800FB91"
            "4C8C43872CF0903B48FB81E5D29E3E45565AB2A6D9F26746D2A0E310F107E903",
            guess_sig_hex);
    res = nl_block_free(&block);
    // Hash of this open block:
    // "70B6BD8B225F62F59EF09D11287DEE95CC07DFA42EADBADA15D8DD4C6AD7C369",
}

TEST_CASE("Sign State Block", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

TEST_CASE("Verify Signature", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

TEST_CASE("Verify Hash", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}
