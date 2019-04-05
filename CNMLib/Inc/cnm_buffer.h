/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Copy & Make Common Library
 * *********************************************************************************************************************
 */

#ifndef CNM_BUFFER_H
#define CNM_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

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

#endif  /* CNM_BUFFER_H */

/* end of file ****************************************************************************************************** */
