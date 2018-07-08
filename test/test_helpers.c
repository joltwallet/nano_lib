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


TEST_CASE("Generate Seed (256-bit entropy)", "[nano_lib]"){
    uint256_t seed_bin;
    hex256_t seed_hex;
    nl_generate_seed(seed_bin);
    sodium_bin2hex(seed_hex, sizeof(seed_hex),
            seed_bin, sizeof(seed_bin));
    strupr(seed_hex);
    printf("Generated Seed: %s\n", seed_hex);
    sodium_memzero(seed_bin, sizeof(seed_bin));
    sodium_memzero(seed_hex, sizeof(seed_hex));
}

