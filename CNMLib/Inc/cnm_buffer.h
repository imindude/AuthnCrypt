/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Copy & Make Common Library
 * *********************************************************************************************************************
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ****************************************************************************************************************** */

struct BufferHandle
{
    uint8_t     *buffer_;
    uint16_t    max_size_;
    uint16_t    used_size_;
};
typedef struct BufferHandle     BufferHandle;

static inline void buif_add_byte_unsafe(BufferHandle *bh, uint8_t byte)
{
    bh->buffer_[bh->used_size_++] = byte;
}

static inline void buif_add_bytes_unsafe(BufferHandle *bh, uint8_t *bs, uint16_t bs_len)
{
    memcpy(bh->buffer_ + bh->used_size_, bs, bs_len);
    bh->used_size_ += bs_len;
}

struct BlockFifo
{
    bool        (*push)(uint8_t*);
    bool        (*take)(uint8_t*);
    uint32_t    (*size)(void);
};
typedef struct BlockFifo    BlockFifo;

struct ByteArray
{
    uint32_t    (*add_byte)(uint8_t);
    uint32_t    (*add_bytes)(uint8_t*, uint32_t);
    void        (*flush)(void);
    void*       (*head)(void);
    void*       (*get)(void);
    bool        (*set)(uint32_t);
    uint32_t    (*size)(void);
    uint32_t    (*limit)(void);
};
typedef struct ByteArray    ByteArray;

#define DEFINE_BLOCKFIFO(NAME)      extern BlockFifo    bf_##NAME
#define DEFINE_BYTEARRAY(NAME)      extern ByteArray    ba_##NAME

/* ****************************************************************************************************************** */

DEFINE_BLOCKFIFO(usbhid);

DEFINE_BYTEARRAY(hidif);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

/* end of file ****************************************************************************************************** */
