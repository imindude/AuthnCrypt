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

    bool        pin_confirmed_;
    uint32_t    counter_;
};
typedef struct DeviceInfo   DeviceInfo;

#define PIN_MIN_LEN             4
#define PIN_MAX_LEN             63
#define PIN_RETRY_MAX           8

struct DeviceAuth
{
    // authenticatorKeyAgreementKey
    uint8_t     key_agreement_pri_[32];
    uint8_t     key_agreement_pub_[64];

    // pinToken
    uint8_t     pin_token_[32];
    // clientPin
    bool        client_pin_;
    int8_t      retry_pin_;                     // PIN_RETRY_MAX
    uint8_t     pin_code_[PIN_MAX_LEN + 1];
    uint8_t     pin_hash_[32];

    // user verification
    bool        uv_;
};
typedef struct DeviceAuth   DeviceAuth;

union DataBlob
{
    struct
    {
        uint8_t     usage_;
        uint32_t    counter_;

        union
        {
            struct
            {
                uint8_t rpid_hash_[32];     // SHA-256(RelyingPartyId)
                uint8_t cred_id_[52];       // CredentialId
                uint8_t user_id_[128];      // UserEntity.id_
                uint8_t disp_name_[256];    // UserEntity.disp_name_
            };
            uint8_t data_[1];
        };
    }
    blob_;
    uint8_t     bytes_[512];    // rpIdHash(32) + credentialId(52) + userId(128) + displayName(256)
};
typedef union DataBlob      DataBlob;

/* ****************************************************************************************************************** */

void        device_init(void);
void        device_reset(void);
void        device_get_rng(uint8_t *bytes, uint32_t len);
DeviceInfo* device_get_info(void);
DeviceAuth* device_get_auth(void);
uint8_t*    device_get_fido_key(uint16_t *size);
uint8_t*    device_get_fido_cert(uint16_t *size);
bool        device_save_blob(DataBlob *blob);
bool        device_load_blob(int16_t index, DataBlob *blob);
bool        device_remove_blob(int16_t index);
int         device_mbedtls_rng(void *handle, unsigned char *output, size_t len);

/* end of file ****************************************************************************************************** */
