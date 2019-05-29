/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "stm32f4xx.h"
#include "app_def.h"
#include "app_device.h"
#include "app_misc.h"
#include "hwl_flash.h"
#include "hwl_button.h"
#include "hwl_led.h"
#include "hwl_rng.h"
#include "hwl_hid.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"

/* ****************************************************************************************************************** */

#define DEVICE_UID_POSTFIX      0x84E9B5C8

#define BLOB_EMPTY      0xFF
#define BLOB_ALIVE      0xF0
#define BLOB_DEAD       0x00

/* ****************************************************************************************************************** */

struct BlobReadIndex
{
    int16_t     rel_index_;
    int16_t     abs_index_;
};
typedef struct BlobReadIndex    BlobReadIndex;

/* ****************************************************************************************************************** */

static DeviceInfo       _device_info;
static DeviceAuth       _device_auth;
static BlobReadIndex    _blob_read_index;

static uint8_t  fido_certificate[] =
{
        0x30, 0x82, 0x02, 0x0e, 0x30, 0x82, 0x01, 0xb4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
        0x84, 0xdc, 0x29, 0x9e, 0xad, 0x01, 0xe3, 0xd9, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x04, 0x03, 0x02, 0x30, 0x62, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x4b, 0x52, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x01, 0x20, 0x31,
        0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x43, 0x6f, 0x70, 0x79, 0x26, 0x4d,
        0x61, 0x6b, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x4d, 0x52,
        0x2e, 0x44, 0x55, 0x44, 0x45, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x69, 0x6d, 0x69, 0x6e, 0x64, 0x75, 0x64, 0x65, 0x40, 0x67,
        0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x33,
        0x31, 0x32, 0x30, 0x39, 0x34, 0x33, 0x35, 0x32, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x33, 0x30,
        0x39, 0x30, 0x39, 0x34, 0x33, 0x35, 0x32, 0x5a, 0x30, 0x62, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x4b, 0x52, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x01, 0x20, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x43, 0x6f,
        0x70, 0x79, 0x26, 0x4d, 0x61, 0x6b, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x07, 0x4d, 0x52, 0x2e, 0x44, 0x55, 0x44, 0x45, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x69, 0x6d, 0x69, 0x6e, 0x64, 0x75,
        0x64, 0x65, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x4c, 0xf6, 0x69, 0xf1, 0xb2, 0x8e, 0xe9, 0x49, 0x1d,
        0x8f, 0xe9, 0x28, 0xa2, 0x2c, 0xea, 0x9c, 0xd2, 0x67, 0x87, 0x57, 0x01, 0xeb, 0x40, 0x26, 0x24,
        0xb0, 0xd3, 0x7e, 0x19, 0x82, 0x96, 0xec, 0xb3, 0x14, 0xfe, 0xb6, 0x77, 0xfd, 0x4c, 0xd5, 0xc1,
        0x1d, 0x7e, 0xa5, 0x74, 0x5a, 0x61, 0xaa, 0x1d, 0xfc, 0xb7, 0xc1, 0x7d, 0x02, 0x1a, 0xe2, 0xf0,
        0x30, 0x1b, 0xfb, 0xf7, 0xa2, 0xcf, 0x51, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55,
        0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x12, 0x52, 0x91, 0x2f, 0x31, 0x51, 0x9e, 0xb9, 0x24, 0xbb,
        0x42, 0x70, 0xce, 0x74, 0x1e, 0x07, 0x55, 0x12, 0xf2, 0xd9, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
        0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x12, 0x52, 0x91, 0x2f, 0x31, 0x51, 0x9e, 0xb9, 0x24,
        0xbb, 0x42, 0x70, 0xce, 0x74, 0x1e, 0x07, 0x55, 0x12, 0xf2, 0xd9, 0x30, 0x0f, 0x06, 0x03, 0x55,
        0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x39,
        0xfe, 0x03, 0x31, 0xc8, 0x7a, 0x8d, 0x21, 0x8d, 0xc4, 0x22, 0x27, 0x70, 0x34, 0x35, 0xde, 0x25,
        0xfb, 0xa0, 0x0a, 0xd2, 0x1e, 0x26, 0x79, 0x58, 0x32, 0xce, 0xdc, 0x5e, 0xbc, 0x89, 0xc2, 0x02,
        0x21, 0x00, 0xc3, 0xac, 0x41, 0x8b, 0xaa, 0x0c, 0xd4, 0x26, 0x12, 0xda, 0x84, 0xf6, 0x8e, 0x44,
        0x3c, 0x30, 0x16, 0x2c, 0x3b, 0x93, 0x3b, 0x2e, 0x5c, 0x1f, 0xf6, 0x11, 0xcb, 0x8b, 0x5d, 0x05,
        0x21, 0xec
};

static uint8_t  fido_private_key[] =
{
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x05, 0xcc, 0xfb, 0xdc, 0xdf, 0x3a, 0x6f, 0xa0, 0xdd,
        0x3f, 0xda, 0x92, 0x3a, 0x35, 0xf5, 0x57, 0x28, 0xbd, 0x23, 0x2d, 0x92, 0xac, 0x4f, 0xf2, 0x47,
        0x3f, 0xe3, 0x39, 0xd8, 0xcb, 0xbf, 0x2c, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x4c, 0xf6, 0x69, 0xf1, 0xb2, 0x8e, 0xe9,
        0x49, 0x1d, 0x8f, 0xe9, 0x28, 0xa2, 0x2c, 0xea, 0x9c, 0xd2, 0x67, 0x87, 0x57, 0x01, 0xeb, 0x40,
        0x26, 0x24, 0xb0, 0xd3, 0x7e, 0x19, 0x82, 0x96, 0xec, 0xb3, 0x14, 0xfe, 0xb6, 0x77, 0xfd, 0x4c,
        0xd5, 0xc1, 0x1d, 0x7e, 0xa5, 0x74, 0x5a, 0x61, 0xaa, 0x1d, 0xfc, 0xb7, 0xc1, 0x7d, 0x02, 0x1a,
        0xe2, 0xf0, 0x30, 0x1b, 0xfb, 0xf7, 0xa2, 0xcf, 0x51
};

/* ****************************************************************************************************************** */

static void init(void)
{
    uint32_t    *uid_base = (uint32_t*)UID_BASE;

    /**
     * generate DeviceInfo
     */

    _device_info.uid_.words_[0] = uid_base[0];
    _device_info.uid_.words_[1] = uid_base[1];
    _device_info.uid_.words_[2] = uid_base[2];
    _device_info.uid_.words_[3] = DEVICE_UID_POSTFIX;

    _device_info.ver_.major_ = VERSION_MAJOR;
    _device_info.ver_.minor_ = VERSION_MINOR;
    _device_info.ver_.build_ = BUILD_NUMBER;

    _device_info.pin_confirmed_ = false;

    /* I think, authentication counter is not need to save. Just increase the number when the dongle is powered on. */

    rng_words(&_device_info.counter_, 1);
    _device_info.counter_ &= 0xFF;

    /**
     * generate DeviceAuth
     */

    uint8_t     buffer[1 + sizeof(_device_auth.key_agreement_pub_) + sizeof(_device_auth.key_agreement_pri_)];
    size_t      size;
    mbedtls_ecdh_context    ecdh_ctx;

    memset(buffer, 0, sizeof(buffer));

    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_ecdh_setup(&ecdh_ctx, MBEDTLS_ECP_DP_SECP256R1);

    do
    {
        mbedtls_ecp_gen_keypair(&ecdh_ctx.grp, &ecdh_ctx.d, &ecdh_ctx.Q, device_mbedtls_rng, NULL);
    }
    while ((mbedtls_ecp_check_privkey(&ecdh_ctx.grp, &ecdh_ctx.d) != 0) ||
            (mbedtls_ecp_check_pubkey(&ecdh_ctx.grp, &ecdh_ctx.Q) != 0));

    // CAUTION!! filled from end of the buffer
    mbedtls_mpi_write_binary(&ecdh_ctx.d, buffer, sizeof(buffer));
    // CAUTION!! filled from start of the buffer
    mbedtls_ecp_point_write_binary(&ecdh_ctx.grp, &ecdh_ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &size, buffer,
            sizeof(buffer));

    mbedtls_ecdh_free(&ecdh_ctx);

    // CAUTION!! filled from end of the buffer
    memcpy(_device_auth.key_agreement_pri_, buffer + 1 + sizeof(_device_auth.key_agreement_pub_),
            sizeof(_device_auth.key_agreement_pri_));
    // CAUTION!! filled from start of the buffer (skip POINT_FORMAT)
    memcpy(_device_auth.key_agreement_pub_, buffer + 1, sizeof(_device_auth.key_agreement_pub_));

    rng_bytes(_device_auth.pin_token_, sizeof(_device_auth.pin_token_));

    _device_auth.retry_pin_ = PIN_RETRY_MAX;

    int16_t     pin_len = check_array_empty(_device_auth.pin_code_, sizeof(_device_auth.pin_code_));

    if (pin_len >= PIN_MIN_LEN)
    {
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), _device_auth.pin_code_, pin_len,
                _device_auth.pin_hash_);
    }
}

static void compact_storage(void)
{
    DataBlob    blob;
    int16_t     r_index = 0;
    int16_t     w_index = 0;

    while (flash_read(r_index, blob.bytes_, sizeof(blob.bytes_)))
    {
        if (blob.blob_.usage_ == BLOB_ALIVE)
        {
            flash_backup_write(w_index, blob.bytes_, sizeof(blob.bytes_));
            w_index++;
        }

        r_index++;
    }

    flash_erase();

    w_index = 0;

    while (flash_backup_read(w_index, blob.bytes_, sizeof(blob.bytes_)))
    {
        if (blob.blob_.usage_ == BLOB_EMPTY)
            break;

        flash_write(w_index, blob.bytes_, sizeof(blob.bytes_));
        w_index++;
    }
}

static void reset_blob_index(void)
{
    _blob_read_index.rel_index_ = 0;
    _blob_read_index.abs_index_ = 0;
}

static uint8_t skip_blob(int16_t index)
{
    DataBlob    blob;
    int16_t     abs_index = _blob_read_index.abs_index_;

    if (_blob_read_index.rel_index_ > index)
        reset_blob_index();

    while (_blob_read_index.rel_index_ < index)
    {
        if (flash_read(abs_index, blob.bytes_, sizeof(blob.bytes_)) == false)
            return BLOB_DEAD;
        if (blob.blob_.usage_ == BLOB_EMPTY)
            return BLOB_EMPTY;

        if (blob.blob_.usage_ == BLOB_ALIVE)
        {
            _blob_read_index.rel_index_++;
            _blob_read_index.abs_index_ = abs_index;
        }
        abs_index++;
    }

    return (_blob_read_index.rel_index_ == index) ? BLOB_ALIVE : BLOB_EMPTY;
}

static bool append_blob(DataBlob *blob)
{
    DataBlob    saved;
    int16_t     abs_index = _blob_read_index.abs_index_;

    while (flash_read(abs_index, saved.bytes_, sizeof(saved.bytes_)))
    {
        if (saved.blob_.usage_ == BLOB_EMPTY)
        {
            blob->blob_.usage_ = BLOB_ALIVE;
            return flash_write(abs_index, blob->bytes_, sizeof(blob->bytes_));
        }
        abs_index++;
    }

    return false;
}

void device_init(void)
{
    flash_init();
    button_init();
    led_init();
    rng_init();
    hid_init();

    init();
    reset_blob_index();
}

void device_reset(void)
{
    flash_erase();
    reset_blob_index();
}

void device_get_rng(uint8_t *bytes, uint32_t len)
{
    rng_bytes(bytes, len);
}

DeviceInfo* device_get_info(void)
{
    return &_device_info;
}

DeviceAuth* device_get_auth(void)
{
    return &_device_auth;
}

uint8_t* device_get_fido_key(uint16_t *size)
{
    if (size)
        *size = sizeof(fido_private_key);

    return fido_private_key;
}

uint8_t* device_get_fido_cert(uint16_t *size)
{
    if (size)
        *size = sizeof(fido_certificate);

    return fido_certificate;
}

bool device_save_blob(DataBlob *blob)
{
    if (append_blob(blob) == false)
    {
        compact_storage();
        reset_blob_index();
        return append_blob(blob);
    }

    return true;
}

bool device_load_blob(int16_t index, DataBlob *blob)
{
    if (skip_blob(index) == BLOB_ALIVE)
    {
        int16_t     abs_index = _blob_read_index.abs_index_;

        while (flash_read(abs_index, blob->bytes_, sizeof(blob->bytes_)))
        {
            if (blob->blob_.usage_ == BLOB_ALIVE)
            {
                _blob_read_index.abs_index_ = abs_index;
                return true;
            }
            else if (blob->blob_.usage_ == BLOB_DEAD)
            {
                abs_index++;
            }
            else
            {
                break;
            }
        }
    }

    return false;
}

bool device_remove_blob(int16_t index)
{
    if (skip_blob(index) == BLOB_ALIVE)
    {
        DataBlob    blob;
        int16_t     abs_index = _blob_read_index.abs_index_;

        while (flash_read(abs_index, blob.bytes_, sizeof(blob.bytes_)))
        {
            if (blob.blob_.usage_ == BLOB_ALIVE)
            {
                blob.blob_.usage_ = BLOB_DEAD;
                flash_write(_blob_read_index.abs_index_, blob.bytes_, sizeof(blob.bytes_));

                _blob_read_index.abs_index_ = abs_index;

                return true;
            }
            else if (blob.blob_.usage_ == BLOB_DEAD)
            {
                abs_index++;
            }
            else
            {
                break;
            }
        }
    }

    return false;
}

/* ****************************************************************************************************************** */

int device_mbedtls_rng(void *dummy, unsigned char *output, size_t len)
{
    (void)dummy;
    rng_bytes(output, len);
    return 0;
}

/* end of file ****************************************************************************************************** */
