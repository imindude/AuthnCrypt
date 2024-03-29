/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Copy & Make Common Library
 * *********************************************************************************************************************
 */

#include <string.h>
#include "cnm_buffer.h"

/* ****************************************************************************************************************** */

#define BLOCKFIFO_CREATE(NAME, BLOCKS, BYTES)\
    static uint32_t __##NAME##_wr = 0;\
    static uint32_t __##NAME##_rd = 0;\
    static uint32_t __##NAME##_sz = 0;\
    static uint8_t  __##NAME##_bf[BYTES * BLOCKS];\
    \
    static bool _bf_##NAME##_push(uint8_t *c)\
    {\
        if (__##NAME##_sz < BLOCKS)\
        {\
            memmove(__##NAME##_bf + __##NAME##_wr * BYTES, c, BYTES);\
            __##NAME##_wr++;\
            if (__##NAME##_wr >= BLOCKS)\
                __##NAME##_wr = 0;\
            __##NAME##_sz++;\
            return true;\
        }\
        return false;\
    }\
    \
    static bool _bf_##NAME##_take(uint8_t *c)\
    {\
        if (c)\
            memmove(c, __##NAME##_bf + __##NAME##_rd * BYTES, BYTES);\
        if ( __##NAME##_sz > 0)\
        {\
            __##NAME##_rd++;\
            if (__##NAME##_rd >= BLOCKS)\
                __##NAME##_rd = 0;\
            __##NAME##_sz--;\
            return true;\
        }\
        return false;\
    }\
    \
    static uint32_t _bf_##NAME##_size(void)\
    {\
        return __##NAME##_sz;\
    }\
    \
    BlockFifo bf_##NAME =\
    {\
            .push = _bf_##NAME##_push,\
            .take = _bf_##NAME##_take,\
            .size = _bf_##NAME##_size,\
    };\

#define BYTEARRAY_CREATE(NAME, LENGTH)\
    static uint8_t __##NAME##_bf[LENGTH];\
    static uint32_t __##NAME##_wr = 0;\
    \
    static uint32_t _ba_##NAME##_add_byte(uint8_t b)\
    {\
        if ((__##NAME##_wr + 1) < LENGTH)\
        {\
            __##NAME##_bf[__##NAME##_wr] = b;\
            __##NAME##_wr++;\
            return __##NAME##_wr;\
        }\
        return 0;\
    }\
    \
    static uint32_t _ba_##NAME##_add_bytes(uint8_t *ba, uint32_t len)\
    {\
        if ((__##NAME##_wr + len) < LENGTH)\
        {\
            memcpy(__##NAME##_bf + __##NAME##_wr, ba, len);\
            __##NAME##_wr += len;\
            return __##NAME##_wr;\
        }\
        return 0;\
    }\
    \
    static bool _ba_##NAME##_insert(uint32_t i, uint8_t b)\
    {\
        if (i < __##NAME##_wr)\
        {\
            __##NAME##_bf[i] = b;\
            return true;\
        }\
        return false;\
    }\
    \
    static void _ba_##NAME##_flush(void)\
    {\
        memset(__##NAME##_bf, 0, LENGTH);\
        __##NAME##_wr = 0;\
    }\
    \
    static void* _ba_##NAME##_head(void)\
    {\
        return (void*)__##NAME##_bf;\
    }\
    \
    \
    static void* _ba_##NAME##_get(void)\
    {\
        return (void*)(__##NAME##_bf + __##NAME##_wr);\
    }\
    \
    static bool _ba_##NAME##_set(bool offset, uint32_t pos)\
    {\
        uint32_t    new_pos = offset ? __##NAME##_wr + pos : pos;\
        \
        if (new_pos < LENGTH)\
        {\
            __##NAME##_wr = new_pos;\
            return true;\
        }\
        return false;\
    }\
    \
    static uint32_t _ba_##NAME##_count(void)\
    {\
        return __##NAME##_wr;\
    }\
    \
    static uint32_t _ba_##NAME##_remain(void)\
    {\
        return LENGTH - __##NAME##_wr;\
    }\
    \
    static uint32_t _ba_##NAME##_max_size(void)\
    {\
        return LENGTH;\
    }\
    \
    ByteArray ba_##NAME =\
    {\
            .add_byte  = _ba_##NAME##_add_byte,\
            .add_bytes = _ba_##NAME##_add_bytes,\
            .insert    = _ba_##NAME##_insert,\
            .flush     = _ba_##NAME##_flush,\
            .head      = _ba_##NAME##_head,\
            .get       = _ba_##NAME##_get,\
            .set       = _ba_##NAME##_set,\
            .count     = _ba_##NAME##_count,\
            .remain    = _ba_##NAME##_remain,\
            .max_size  = _ba_##NAME##_max_size,\
    };\

/* ****************************************************************************************************************** */

BLOCKFIFO_CREATE(usbhid, 128, 64)

BYTEARRAY_CREATE(hidif, 4096)

/* end of file ****************************************************************************************************** */
