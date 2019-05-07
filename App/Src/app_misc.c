/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "app_misc.h"
#include "app_device.h"
#include "fidodef.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"

/* ****************************************************************************************************************** */

void make_ctap1_tag(uint8_t *param, int16_t param_len, uint8_t *key, int16_t key_len, uint8_t *tag)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);      // HMAC ready
    mbedtls_md_hmac_starts(&md_ctx, param, param_len);
    mbedtls_md_hmac_update(&md_ctx, device_get_info()->uid_.bytes_, DEVICE_UID_SIZE);
    mbedtls_md_hmac_update(&md_ctx, key, key_len);
    mbedtls_md_hmac_finish(&md_ctx, tag);
    mbedtls_md_free(&md_ctx);
}

void make_ctap2_tag(uint8_t *param, int16_t param_len, uint8_t *seed, int16_t seed_len, uint32_t count, uint8_t *tag)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    mbedtls_md_hmac_starts(&md_ctx, device_get_info()->uid_.bytes_, DEVICE_UID_SIZE);
    mbedtls_md_hmac_update(&md_ctx, param, param_len);
    mbedtls_md_hmac_update(&md_ctx, seed, seed_len);
    mbedtls_md_hmac_update(&md_ctx, device_get_info()->uid_.bytes_, DEVICE_UID_SIZE);
    mbedtls_md_hmac_update(&md_ctx, (uint8_t*)&count, 4);
    mbedtls_md_hmac_finish(&md_ctx, tag);
    mbedtls_md_free(&md_ctx);
}

/* end of file ****************************************************************************************************** */
