/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#pragma once

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

struct DeviceInfo
{
    union
    {
        uint32_t    words_[4];
        uint8_t     bytes_[16];
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

struct DeviceAuth
{
    // authenticatorKeyAgreementKey
    uint8_t     key_agreement_pri_[32];
    uint8_t     key_agreement_pub_[64];

    // pinToken
    uint8_t     pin_token_[32];
    // clientPin
    bool        client_pin_;

    // user verification
    bool        uv_;
};
typedef struct DeviceAuth   DeviceAuth;

union DataBlob
{
    struct
    {
        uint8_t usage_;
        uint8_t data_[1];
    }
    blob_;
    uint8_t     bytes_[512];
};
typedef union DataBlob      DataBlob;

/* ****************************************************************************************************************** */

void        device_init(void);
void        device_get_rng(uint8_t *bytes, uint32_t len);
DeviceInfo* device_get_info(void);
DeviceAuth* device_get_auth(void);
uint8_t*    device_get_fido_key(uint16_t *size);
uint8_t*    device_get_fido_cert(uint16_t *size);
uint32_t    device_get_counter(void);
bool        device_save_blob(DataBlob *blob);
bool        device_load_blob(int16_t index, DataBlob *blob);
int         device_mbedtls_rng(void *handle, unsigned char *output, size_t len);

/* end of file ****************************************************************************************************** */
