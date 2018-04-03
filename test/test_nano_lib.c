#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include "sodium.h"

#include "nano_lib.h"
#include "helpers.h"

TEST_CASE("HEX_256 to BIN_256", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

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

#if 0
TEST_CASE("Seed To Public Address", "[nano_lib]"){
    /* Tests all the way from Seed to Public Address.
     *
     * Tests multiple indices.
     *
     * Test values were sourced from the official reference rai_node
     *
     * Todo:
     * - [N] seed to private
     * - [N] private to public
     * - [N] public to address
     * */
    TEST_IGNORE_MESSAGE("Not Implemented");

    hex256_t test_seed_hex;
    uint32_t test_index;

    hex256_t correct_private_key_hex;
    hex256_t correct_public_key_hex;

    char correct_address[ADDRESS_BUF_LEN];
    char guess_address[ADDRESS_BUF_LEN];

    nl_err_t res;
    
    /* Test 1 (Generic)*/
    strcpy(test_seed_hex,
            "1A620665F60713F867D7D7F77BA337360B303C8C3C94E84819C4E282B6EAC262");
    test_index = 0;

    res = nl_public_to_address(guess_address,
            sizeof(guess_public_address),
            test_public_key);
    if(res != E_SUCCESS){
        //todo: test fail
    }
    TEST_ASSERT_EQUAL_STRING(guess_address,
            "xrb_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9");

#if 0
    correct_private_key_hex = \
            "xrb_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9";
    correct_public_key_hex = \
            "68D2CEA554187DDF4891E2BDC7AB7442F230A650826455411401B41EEC9BED31";
    correct_public_address = \
            "xrb_1t8kstkoa85xux6b5roxryoqaiqk84m731m6co1ja1fn5upbqubj34osorm9";




    /* Test 2 (Testing non-zero index)*/
    test_seed_hex = \
            "1A620665F60713F867D7D7F77BA337360B303C8C3C94E84819C4E282B6EAC262";
    test_index = 1;
    correct_private_key_hex = \
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E";
    correct_public_key_hex = \
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17";
    correct_public_address = \
            "xrb_1pp56dwpqotnffqqdd543bfz4oq9dc53c9m6qp6xwdkoghpi3uiqwnxanucp";

#endif
}

TEST_CASE("Sign Digest", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

TEST_CASE("Sign Send Block", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
    char test_private_key_hex[HEX_256];
    char block_buf[BLOCK_BUF_LEN];
    char test_work_hex[HEX_64];
    char correct_signature[HEX_512];

    /* Test 1 */
    test_private_key_hex = \
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E";
    test_work_hex = "f0f4d56c95d3e7e5";
    correct_signature = "A9807C7103BFD6D1A19E128F0D0318FAEF042E6A4497F7D53F1755"
            "8043DB022553B8B5259C0C317E771437A1790D613678F8EA954BE0B0157F16611C"
            "8195ED0B";
    // Todo: Convert this json representation into a struc representation
    /* {
     *     "hash": "6447171713541D387BAB4161E6BA40A88F41140218395DCCA0230BC29827717A",
     *         "block": "{    "type": "send",    "previous": "00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C00BAB10C",    "destination": "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8",    "balance": "000000000031AC4CF7AC832410B9E799",    "work": "f0f4d56c95d3e7e5",    "signature": "A9807C7103BFD6D1A19E128F0D0318FAEF042E6A4497F7D53F17558043DB022553B8B5259C0C317E771437A1790D613678F8EA954BE0B0157F16611C8195ED0B"}"
     *         }
     */
    //test_seed_hex = "1A620665F60713F867D7D7F77BA337360B303C8C3C94E84819C4E282B6EAC262";
    //test_index = 1;
    //correct_private_key_hex = "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E";
    correct_public_key_hex = \
            "5AC322F96BD7546B6F75AC620A5BF156E75A86151E64BD89DE2E5573ED00EE17";
    correct_public_address = \
            "xrb_1pp56dwpqotnffqqdd543bfz4oq9dc53c9m6qp6xwdkoghpi3uiqwnxanucp";

}

TEST_CASE("Sign Receive Block", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
    char test_private_key_hex[HEX_256];
    char block_buf[BLOCK_BUF_LEN];
    char test_work_hex[HEX_64];
    char correct_signature[HEX_512];

    /* Test 1 */
    test_private_key_hex = \
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E";
    test_work_hex = "f22c729331e5efb3";
    correct_signature = "C557AFF3388FA6372EC65D4A6C7256BFC2DCEE5E734C1B57B57910"
            "95A79102289BBF5CE676D0A9451AB90314124A07653E9169AAABB82628BA57A1A3"
            "DD057A0E";
    // Todo: Coynvert this json representation into a struc representation
    /* {
     *     "hash": "AB67B959665FD6CE8B947196E8B0D00DE5D07FA38BE0938966530226D7F52446",
     *         "block": "{    "type": "receive",    "previous": "AF9C1D46AAE66CC8F827904ED02D4B3D95AA98B1FF058352BA6B670BEFD40231",    "source": "6447171713541D387BAB4161E6BA40A88F41140218395DCCA0230BC29827717A",    "work": "f22c729331e5efb3",    "signature": "C557AFF3388FA6372EC65D4A6C7256BFC2DCEE5E734C1B57B5791095A79102289BBF5CE676D0A9451AB90314124A07653E9169AAABB82628BA57A1A3DD057A0E"}"
     *         }
     */
}

TEST_CASE("Sign Change Block", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
    char test_private_key_hex[HEX_256];
    char block_buf[BLOCK_BUF_LEN];
    char test_work_hex[HEX_64];
    char correct_signature[HEX_512];
    char test_rep[ADDRESS_BUF_LEN];

    /* Test 1 */
    test_private_key_hex = \
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E";
    test_work_hex = "3a74e84a07e6837c";
    correct_signature = "93E243440E64E44C7D33359F15B18EA3FC5E5A5B3EFB3996F1B05D"
            "436AF200E91C6DBC16E0C62142776A0FAE393C85F43FAD16C5227225EA87E1FD08"
            "A46B4605";

    // Todo: Convert this json representation into a struc representation
    /* {
     *     "hash": "EFFACC9470702D3280FFDC22D1FA2922CB6BB85C86A4CEAAD6E68B63F607F3EC",
     *         "block": "{\n    \"type\": \"change\",\n    \"previous\": \"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\",\n    \"representative\": \"xrb_3dmtrrws3pocycmbqwawk6xs7446qxa36fcncush4s1pejk16ksbmakis78m\",\n    \"work\": \"3a74e84a07e6837c\",\n    \"signature\": \"93E243440E64E44C7D33359F15B18EA3FC5E5A5B3EFB3996F1B05D436AF200E91C6DBC16E0C62142776A0FAE393C85F43FAD16C5227225EA87E1FD08A46B4605\"\n}\n"
     *         }
     */
}

TEST_CASE("Sign Open Block", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");

    char test_private_key_hex[HEX_256];
    char block_buf[BLOCK_BUF_LEN];
    char test_work_hex[HEX_64];
    char correct_signature[HEX_512];
    char test_rep[ADDRESS_BUF_LEN];

    /* Test 1 */
    test_private_key_hex = \
            "18E8AC0BD5EFB59BF047A32A2E501D3FDB97D7439D91BD1D53F49FFE54E1F92E";
    test_work_hex = "d2183f1b5b08a7a8";
    correct_signature = "12776A6DBF21AD285EAA187EC9E7BDF622C18AAFE765100CA62FCD"
            "4C7800FB914C8C43872CF0903B48FB81E5D29E3E45565AB2A6D9F26746D2A0E310"
            "F107E903";

    // Todo: Convert this json representation into a struc representation
    /* {
     *     "hash": "70B6BD8B225F62F59EF09D11287DEE95CC07DFA42EADBADA15D8DD4C6AD7C369",
     *         "block": "{    "type": "open",    "source": "BA5920AF3B105AB472DDD31100000F3952BA1BACCC4212874219064538BADFAA",    "representative": "xrb_1cwswatjifmjnmtu5toepkwca64m7qtuukizyjxsghujtpdr9466wjmn89d8",    "account": "xrb_1pp56dwpqotnffqqdd543bfz4oq9dc53c9m6qp6xwdkoghpi3uiqwnxanucp",    "work": "d2183f1b5b08a7a8",    "signature":
     *         "12776A6DBF21AD285EAA187EC9E7BDF622C18AAFE765100CA62FCD4C7800FB914C8C43872CF0903B48FB81E5D29E3E45565AB2A6D9F26746D2A0E310F107E903"}"
     *         }
     */
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

TEST_CASE("Sign Message", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}
#endif
