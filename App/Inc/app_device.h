/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#ifndef APP_DEVICE_H
#define APP_DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

#define DEVICE_UID_SIZE     32

struct DeviceInfo
{
    union
    {
        uint32_t    words_[3];
        uint8_t     bytes_[DEVICE_UID_SIZE];
    }
    uid_;

    struct
    {
        uint8_t     major_;
        uint8_t     minor_;
        uint32_t    build_;
    }
    ver_;

    bool    pin_confirmed_;
};
typedef struct DeviceInfo   DeviceInfo;

/* ****************************************************************************************************************** */

void        device_init(void);
DeviceInfo* device_get_info(void);
uint8_t*    device_get_fido_key(uint16_t *size);
uint8_t*    device_get_fido_cert(uint16_t *size);
uint32_t    device_get_counter(void);
int         device_mbedtls_rng(void *handle, unsigned char *output, size_t len);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* APP_DEVICE_H */

/* end of file ****************************************************************************************************** */
