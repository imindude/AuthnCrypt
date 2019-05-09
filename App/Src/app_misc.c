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

void make_fido_tag(uint8_t *param, int16_t param_len, uint8_t *nonce, int16_t nonce_len, uint8_t *tag)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    mbedtls_md_hmac_starts(&md_ctx, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_));
    mbedtls_md_hmac_update(&md_ctx, param, param_len);
    mbedtls_md_hmac_update(&md_ctx, nonce, nonce_len);
    mbedtls_md_hmac_update(&md_ctx, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_));
    mbedtls_md_hmac_finish(&md_ctx, tag);
    mbedtls_md_free(&md_ctx);
}

bool check_array_empty(uint8_t *array, uint32_t len)
{
    bool    result = true;

    for (uint32_t i = 0; i < len; i++)
        if (array[i] != 0)
            result = false;

    return result;
}

/* end of file ****************************************************************************************************** */
