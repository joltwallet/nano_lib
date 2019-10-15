#ifndef NANO_LIB_HASH_WRAPPER_H__
#define NANO_LIB_HASH_WRAPPER_H__

#include "sdkconfig.h"

#if CONFIG_NANO_LIB_CUSTOM_HASH
    #include "../../nl_hash.h"
#else
    #include "hash_default.h"
#endif

#endif

