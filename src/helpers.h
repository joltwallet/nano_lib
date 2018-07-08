/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#ifndef __NANO_LIB_HELPERS_H__
#define __NANO_LIB_HELPERS_H__

#include <byteswap.h>

#ifndef bswap_64
#define bswap_64(x) __bswap_64(x)
#endif

#ifndef bswap_32
#define bswap_32(x) __bswap_32(x)
#endif

void strupper(char *s);
void strnupper(char *s, const int n);
void strlower(char *s);
void strnlower(char *s, const int n);

void nl_generate_seed(uint256_t seed_bin);

#endif
