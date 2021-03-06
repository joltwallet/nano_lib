/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <newlib.h>
#include <esp_system.h>
#include "sodium.h"
#include "esp_timer.h"

#include "jolttypes.h"
#include "nano_lib.h"

TEST_CASE("Verify PoW", "[nano_lib]"){
    /* Note that nl_pow_verify returns 0 (False, E_SUCCESS) on Success */
    jolt_err_t res;
    uint256_t previous;
    uint64_t work;

    /* Valid Work */
    sodium_hex2bin(previous, sizeof(previous),
            "FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0",
            HEX_256, NULL, NULL, NULL);
    res = nl_parse_server_work_string("677d7dcc1e358b37", &work);
    TEST_ASSERT_FALSE(res);
    res = nl_pow_verify(previous, work);
    TEST_ASSERT_TRUE(res);

    /* Invalid Work */
    sodium_hex2bin(previous, sizeof(previous),
            "FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0",
            HEX_256, NULL, NULL, NULL);
    res = nl_parse_server_work_string("677d7dcc1e358b38", &work);
    TEST_ASSERT_FALSE(res);
    res = nl_pow_verify(previous, work);
    TEST_ASSERT_FALSE(res);
}

TEST_CASE("Compute Local PoW", "[nano_lib]"){
    #if CONFIG_NANO_LIB_POW_UNIT_TEST_IGNORE
    TEST_IGNORE_MESSAGE("Skipping Compute Local PoW Test");
    #endif

    jolt_err_t res;
    uint64_t t_start;
    uint64_t t_end;
    uint32_t t_duration;
    uint256_t previous;
    uint64_t work;

    for(int i = 0; i<10; i++){
        nl_generate_seed(previous);
        t_start = esp_timer_get_time();
        work = nl_compute_local_pow(previous, 0);
        t_end = esp_timer_get_time();
        t_duration = (t_end - t_start) / 1000000;
        res = nl_pow_verify(previous, work);
        TEST_ASSERT_TRUE(res);
        printf("PoW %d time: %ds\n", i, t_duration);
    }
}
