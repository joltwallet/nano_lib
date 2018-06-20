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

#include "nano_lib.h"
#include "helpers.h"


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

