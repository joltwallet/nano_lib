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
#include "nano_lib.h"


TEST_CASE("Verify Block Hash", "[nano_lib]"){
    uint256_t guess_hash_bin;
    hex256_t guess_hash_hex;
    nl_block_t block;

    /* Test State Block */
    nl_block_init(&block);
    block.type = STATE;
    sodium_hex2bin(block.account, sizeof(block.account),
            "C1CD33D62CC72FAC1294C990D4DD2B02A4DB85D42F220C48C13AF288FB21D4C1",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.link, sizeof(block.link),
            "B2EC73C1F503F47E051AD72ECB512C63BA8E1A0ACC2CEE4EA9A22FE1CBDB693F",
            HEX_256, NULL, NULL, NULL);
    nl_address_to_public(block.representative,
            "xrb_3p1asma84n8k84joneka776q4egm5wwru3suho9wjsfyuem8j95b3c78nw8j");
    nl_parse_server_work_string("677d7dcc1e358b37", &(block.work));

    mbedtls_mpi_read_string(&(block.balance), 10,
            "5000000000000000000000000000001");

    nl_block_compute_hash(&block, guess_hash_bin);
    nl_block_free(&block);

    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex),
            guess_hash_bin, sizeof(guess_hash_bin));
    strupr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "597395E83BD04DF8EF30AF04234EAAFE0606A883CF4AEAD2DB8196AAF5C4444F",
            guess_hash_hex);

    /* Test Send Block */
    nl_block_init(&block);
    block.type = SEND;
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C",
            HEX_256, NULL, NULL, NULL);
    nl_address_to_public(block.link,
            "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8");
    nl_parse_server_work_string("f0f4d56c95d3e7e5", &(block.work));

    // Compute final account balance
    mbedtls_mpi transaction_amount;
    mbedtls_mpi_init(&transaction_amount);
    mbedtls_mpi_read_string(&transaction_amount, 10, "87593489348637673");

    // Original Amount
    mbedtls_mpi_read_string(&(block.balance), 10, "60051032083097114097032066");
    // Subtract Transaction Amount from the Original Amount
    mbedtls_mpi_sub_mpi(&(block.balance), &(block.balance), &transaction_amount);

    nl_block_compute_hash(&block, guess_hash_bin);
    mbedtls_mpi_free(&transaction_amount);
    nl_block_free(&block);

    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex),
            guess_hash_bin, sizeof(guess_hash_bin));
    strupr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "6447171713541D387BAB4161E6BA40A88F41140218395DCCA0230BC29827717A",
            guess_hash_hex);

    /* Test Receive Block */
    nl_block_init(&block);
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
    nl_parse_server_work_string("f22c729331e5efb3", &(block.work));

    nl_block_compute_hash(&block, guess_hash_bin);
    nl_block_free(&block);

    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex),
            guess_hash_bin, sizeof(guess_hash_bin));
    strupr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "AB67B959665FD6CE8B947196E8B0D00DE5D07FA38BE0938966530226D7F52446",
            guess_hash_hex);

    /* Test Open Block */
    nl_block_init(&block);
    block.type = OPEN;
    nl_address_to_public(block.representative,
            "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8");
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    nl_parse_server_work_string("d2183f1b5b08a7a8", &(block.work));
    sodium_hex2bin(block.link, sizeof(block.link),
            "BA5920AF3B105AB472DDD31100000F3952BA1BACCC4212874219064538BADFAA",
            HEX_256, NULL, NULL, NULL);

    nl_block_compute_hash(&block, guess_hash_bin);
    nl_block_free(&block);

    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex),
            guess_hash_bin, sizeof(guess_hash_bin));
    strupr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "70B6BD8B225F62F59EF09D11287DEE95CC07DFA42EADBADA15D8DD4C6AD7C369",
            guess_hash_hex);

    /* Test Change Block */
    nl_block_init(&block);
    block.type = CHANGE;
    nl_address_to_public(block.representative,
            "xrb_3dmtrrws3pocycmbqwawk6xs7446qxa36fcncush4s1pejk16ksbmakis78m");
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            HEX_256, NULL, NULL, NULL);
    nl_parse_server_work_string("3a74e84a07e6837c", &(block.work));

    nl_block_compute_hash(&block, guess_hash_bin);
    nl_block_free(&block);

    sodium_bin2hex(guess_hash_hex, sizeof(guess_hash_hex),
            guess_hash_bin, sizeof(guess_hash_bin));
    strupr(guess_hash_hex);
    TEST_ASSERT_EQUAL_STRING(
            "EFFACC9470702D3280FFDC22D1FA2922CB6BB85C86A4CEAAD6E68B63F607F3EC",
            guess_hash_hex);
}

TEST_CASE("Sign State Block", "[nano_lib]"){
    jolt_err_t res;
    hex512_t guess_sig_hex;
    CONFIDENTIAL uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "B61AEB236B0C8A2DFDD71C06F1F3544C524801E4B45B7A34DFDEC6F74F177927",
            HEX_256, NULL, NULL, NULL);

    nl_block_init(&block);
    block.type = STATE;
    sodium_hex2bin(block.account, sizeof(block.account),
            "C1CD33D62CC72FAC1294C990D4DD2B02A4DB85D42F220C48C13AF288FB21D4C1",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.link, sizeof(block.link),
            "B2EC73C1F503F47E051AD72ECB512C63BA8E1A0ACC2CEE4EA9A22FE1CBDB693F",
            HEX_256, NULL, NULL, NULL);
    nl_address_to_public(block.representative,
            "xrb_3p1asma84n8k84joneka776q4egm5wwru3suho9wjsfyuem8j95b3c78nw8j");
    nl_parse_server_work_string("677d7dcc1e358b37", &(block.work));
    mbedtls_mpi_read_string(&(block.balance), 10,
            "5000000000000000000000000000001");

    res = nl_block_sign(&block, test_private_key_bin);
    sodium_memzero(test_private_key_bin, sizeof(test_private_key_bin));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_block_sign returned an unsuccessful code");

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupr(guess_sig_hex);
    nl_block_free(&block);
    TEST_ASSERT_EQUAL_STRING(
            "90CBD62F5466E35DB3BFE5EFDBC6283BD30C0591A3787C9458D11F2AF6188E45"
            "E6E71B5F4A8E3598B1C80080D6024867878E355161AD1935CD757477991D3B0B",
            guess_sig_hex);
}

TEST_CASE("Sign Send Block", "[nano_lib]"){
    jolt_err_t res;
    hex512_t guess_sig_hex;
    CONFIDENTIAL uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    nl_block_init(&block);
    block.type = SEND;
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C",
            HEX_256, NULL, NULL, NULL);
    nl_address_to_public(block.link,
            "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8");
    nl_parse_server_work_string("f0f4d56c95d3e7e5", &(block.work));

    // Compute final account balance
    mbedtls_mpi transaction_amount;
    mbedtls_mpi_init(&transaction_amount);
    mbedtls_mpi_read_string(&transaction_amount, 10, "87593489348637673");

    // Original Amount
    mbedtls_mpi_read_string(&(block.balance), 10, "60051032083097114097032066");
    // Subtract Transaction Amount from the Original Amount
    mbedtls_mpi_sub_mpi(&(block.balance), &(block.balance), &transaction_amount);

    res = nl_block_sign(&block, test_private_key_bin);
    sodium_memzero(test_private_key_bin, sizeof(test_private_key_bin));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_block_sign returned an unsuccessful code");

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupr(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "A9807C7103BFD6D1A19E128F0D0318FAEF042E6A4497F7D53F17558043DB0225"
            "53B8B5259C0C317E771437A1790D613678F8EA954BE0B0157F16611C8195ED0B",
            guess_sig_hex);
    mbedtls_mpi_free(&transaction_amount);
    nl_block_free(&block);
}

TEST_CASE("Sign Receive Block", "[nano_lib]"){
    jolt_err_t res;
    hex512_t guess_sig_hex;
    CONFIDENTIAL uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    nl_block_init(&block);
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
    nl_parse_server_work_string("f22c729331e5efb3", &(block.work));

    res = nl_block_sign(&block, test_private_key_bin);
    sodium_memzero(test_private_key_bin, sizeof(test_private_key_bin));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_block_sign returned an unsuccessful code");

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupr(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "C557AFF3388FA6372EC65D4A6C7256BFC2DCEE5E734C1B57B5791095A7910228"
            "9BBF5CE676D0A9451AB90314124A07653E9169AAABB82628BA57A1A3DD057A0E",
            guess_sig_hex);
    nl_block_free(&block);
}

TEST_CASE("Sign Change Block", "[nano_lib]"){
    jolt_err_t res;
    hex512_t guess_sig_hex;
    CONFIDENTIAL uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    nl_block_init(&block);
    block.type = CHANGE;
    nl_address_to_public(block.representative,
            "xrb_3dmtrrws3pocycmbqwawk6xs7446qxa36fcncush4s1pejk16ksbmakis78m");
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            HEX_256, NULL, NULL, NULL);
    nl_parse_server_work_string("3a74e84a07e6837c", &(block.work));

    res = nl_block_sign(&block, test_private_key_bin);
    sodium_memzero(test_private_key_bin, sizeof(test_private_key_bin));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_block_sign returned an unsuccessful code");


    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupr(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "93E243440E64E44C7D33359F15B18EA3FC5E5A5B3EFB3996F1B05D436AF200E9"
            "1C6DBC16E0C62142776A0FAE393C85F43FAD16C5227225EA87E1FD08A46B4605",
            guess_sig_hex);
    nl_block_free(&block);
}

TEST_CASE("Sign Open Block", "[nano_lib]"){
    jolt_err_t res;
    hex512_t guess_sig_hex;
    CONFIDENTIAL uint256_t test_private_key_bin;
    nl_block_t block;

    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E",
            HEX_256, NULL, NULL, NULL);

    nl_block_init(&block);
    block.type = OPEN;
    nl_address_to_public(block.representative,
            "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8");
    sodium_hex2bin(block.account, sizeof(block.account),
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17",
            HEX_256, NULL, NULL, NULL);
    nl_parse_server_work_string("d2183f1b5b08a7a8", &(block.work));
    sodium_hex2bin(block.link, sizeof(block.link),
            "BA5920AF3B105AB472DDD31100000F3952BA1BACCC4212874219064538BADFAA",
            HEX_256, NULL, NULL, NULL);

    res = nl_block_sign(&block, test_private_key_bin);
    sodium_memzero(test_private_key_bin, sizeof(test_private_key_bin));
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_block_sign returned an unsuccessful code");

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupr(guess_sig_hex);
    TEST_ASSERT_EQUAL_STRING(
            "12776A6DBF21AD285EAA187EC9E7BDF622C18AAFE765100CA62FCD4C7800FB91"
            "4C8C43872CF0903B48FB81E5D29E3E45565AB2A6D9F26746D2A0E310F107E903",
            guess_sig_hex);
    nl_block_free(&block);
}

