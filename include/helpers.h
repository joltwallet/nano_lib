/* nano_lib - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software Foundation,
 Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
