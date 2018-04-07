#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_system.h>
#include "sodium.h"

#include "nano_lib.h"
#include "helpers.h"

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
    /* Using test vectors from:
     * https://github.com/trezor/python-mnemonic/blob/master/vectors.json
     */
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
    /* Using test vectors from:
     * https://github.com/trezor/python-mnemonic/blob/master/vectors.json
     */
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

TEST_CASE("Nano Seed From Mneumonic", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
    /* Use's Roosmaa's BIP39 Demo as reference for test case 
     * https://github.com/roosmaa/nano-bip39-demo */
    // "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur" -password "some password" -path "44'/165'/0'"
    // Private key: 3be4fc2ef3f3b7374e6fc4fb6e7bb153f8a2998b3b3dab50853eabe128024143
    // Public key: 5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4
    // Nano address: nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d
}

TEST_CASE("String Case Helpers", "[nano_lib]"){
    char buf[10];
    const char test_string[] = "NanO123$";

    strlcpy(buf, test_string, sizeof(buf));
    strupper(buf);
    TEST_ASSERT_EQUAL_STRING("NANO123$", buf);

    strlcpy(buf, test_string, sizeof(buf));
    strnupper(buf, 2);
    TEST_ASSERT_EQUAL_STRING("NAnO123$", buf);

    strlcpy(buf, test_string, sizeof(buf));
    strlower(buf);
    TEST_ASSERT_EQUAL_STRING("nano123$", buf);

    strlcpy(buf, test_string, sizeof(buf));
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
    sodium_memzero(seed_bin, sizeof(seed_bin));
    sodium_memzero(seed_hex, sizeof(seed_hex));
}

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

TEST_CASE("Private Key To Public Key", "[nano_lib]"){
	nl_err_t res;
    uint256_t test_private_key_bin;
    uint256_t guess_public_key_bin;
    hex256_t guess_public_key_hex;

    /* Test Case 1 - Normal Use */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin), \
            "102A1BD8E50D314B1AF18B064763836500961D97E1517B409D9797E37F148290",
            HEX_256, NULL, NULL, NULL);
	res = nl_private_to_public(guess_public_key_bin, test_private_key_bin);
    TEST_ASSERT_EQUAL_INT_MESSAGE(E_SUCCESS, res,
            "nl_private_to_public returned an unsuccessful code");
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

TEST_CASE("Sign State Block", "[nano_lib]"){
    nl_err_t res;
    hex512_t guess_sig_hex;
    uint256_t test_private_key_bin;
    nl_block_t block;

    /* Test 1 */
    sodium_hex2bin(test_private_key_bin, sizeof(test_private_key_bin),
            "B61AEB236B0C8A2DFDD71C06F1F3544C524801E4B45B7A34DFDEC6F74F177927",
            HEX_256, NULL, NULL, NULL);

    res = nl_block_init(&block);
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
    res = nl_address_to_public(block.representative,
            "xrb_3p1asma84n8k84joneka776q4egm5wwru3suho9wjsfyuem8j95b3c78nw8j");
    // Probably not valid work, but it doesn't matter
    sodium_hex2bin(block.work, sizeof(block.work),
            "0000000000000000", HEX_64, NULL, NULL, NULL);
    mbedtls_mpi_read_string(&(block.balance), 10,
            "5000000000000000000000000000001");

    res = nl_sign_block(&block, test_private_key_bin);

    sodium_bin2hex(guess_sig_hex, sizeof(guess_sig_hex),
            block.signature, sizeof(block.signature));
    strupper(guess_sig_hex);
    nl_block_free(&block);
    TEST_ASSERT_EQUAL_STRING(
            "90CBD62F5466E35DB3BFE5EFDBC6283BD30C0591A3787C9458D11F2AF6188E45"
            "E6E71B5F4A8E3598B1C80080D6024867878E355161AD1935CD757477991D3B0B",
            guess_sig_hex);

    // Hash of this state block:
    // "hash": "597395E83BD04DF8EF30AF04234EAAFE0606A883CF4AEAD2DB8196AAF5C4444F"
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

TEST_CASE("Verify Signature", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}

TEST_CASE("Verify Hash", "[nano_lib]"){
    TEST_IGNORE_MESSAGE("Not Implemented");
}
