#ifndef __NANO_LIB_HELPERS_H__
#define __NANO_LIB_HELPERS_H__

void strupper(char *s);
void strnupper(char *s, const int n);
void strlower(char *s);
void strnlower(char *s, const int n);

void int_to_char_array(unsigned char *char_arr, uint32_t data);
void nl_generate_seed(uint256_t seed_bin);

#endif
