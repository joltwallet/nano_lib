#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <newlib.h>
#include <esp_system.h>
#include "sodium.h"

#include "nano_lib.h"
#include "helpers.h"

TEST_CASE("Verify PoW", "[nano_lib]"){
    nl_block_t block;
    nl_err_t res;

    nl_block_init(&block);
    sodium_hex2bin(block.previous, sizeof(block.previous),
            "FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0",
            HEX_256, NULL, NULL, NULL);
    block.work = nl_parse_server_work_string("677d7dcc1e358b37");
    res = nl_block_pow_verify(&block);
    nl_block_free(&block);
    TEST_ASSERT_FALSE(res);
}
