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

void write_be(uint8_t *data, uint32_t x); //deprecate this  
void write_be64(uint8_t *data, uint64_t x); //deprecate this
void nl_generate_seed(uint256_t seed_bin);

#endif
