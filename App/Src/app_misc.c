/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "stm32f4xx.h"
#include "app_misc.h"
#include "app_device.h"
#include "fidodef.h"
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"

/* ****************************************************************************************************************** */

void make_fido_tag(uint8_t *param, int16_t param_len, uint8_t *nonce, int16_t nonce_len, uint8_t *tag)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    if (param && (param_len > 0))
        mbedtls_md_hmac_starts(&md_ctx, param, param_len);
    mbedtls_md_hmac_update(&md_ctx, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_));
    if (nonce && (nonce_len) > 0)
        mbedtls_md_hmac_update(&md_ctx, nonce, nonce_len);
    mbedtls_md_hmac_update(&md_ctx, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_));
    mbedtls_md_hmac_finish(&md_ctx, tag);
    mbedtls_md_free(&md_ctx);
}

uint8_t make_attestation_sign(uint8_t *data, uint16_t data_size, uint8_t *sign_der)
{
    mbedtls_pk_context  pk_ctx;
    size_t      size;
    uint16_t    fido_key_size;
    uint8_t     *fido_key = device_get_fido_key(&fido_key_size);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(&pk_ctx, fido_key, fido_key_size, NULL, 0);
    mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256, data, data_size, sign_der, &size, device_mbedtls_rng, NULL);
    mbedtls_pk_free(&pk_ctx);

    return size;
}

void make_secp256r1_private_key(uint8_t *param, int16_t param_len, uint8_t *private_key)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    mbedtls_md_hmac_starts(&md_ctx, param, param_len);
    mbedtls_md_hmac_update(&md_ctx, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_));
    mbedtls_md_hmac_finish(&md_ctx, private_key);
    mbedtls_md_free(&md_ctx);
}

void make_secp256r1_public_key(uint8_t *private_key, uint8_t *x, uint8_t *y)
{
    mbedtls_ecp_keypair ecp_kp;
    size_t  size;
    uint8_t buffer[1 + SECP256R1_PUBLIC_KEY_SIZE];    // key format 1byte

    mbedtls_ecp_keypair_init(&ecp_kp);
    mbedtls_ecp_group_load(&ecp_kp.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&ecp_kp.d, private_key, SECP256R1_PRIVATE_KEY_SIZE);
    mbedtls_ecp_mul(&ecp_kp.grp, &ecp_kp.Q, &ecp_kp.d, &ecp_kp.grp.G, device_mbedtls_rng, NULL);
    mbedtls_ecp_point_write_binary(&ecp_kp.grp, &ecp_kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &size, buffer, sizeof(buffer));

    memcpy(x, buffer + 1, SECP256R1_PUBLIC_KEY_X_SIZE);
    memcpy(y, buffer + 1 + SECP256R1_PUBLIC_KEY_X_SIZE, SECP256R1_PUBLIC_KEY_Y_SIZE);
}

void get_authenticator_secret(uint8_t *x, uint8_t *y, uint8_t *shared_secret)
{
    mbedtls_ecdh_context    ecdh_ctx;
    size_t      size;

    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_ecdh_setup(&ecdh_ctx, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&ecdh_ctx.d, device_get_auth()->key_agreement_pri_, SECP256R1_PRIVATE_KEY_SIZE);
    mbedtls_mpi_read_binary(&ecdh_ctx.Qp.X, x, SECP256R1_PUBLIC_KEY_X_SIZE);
    mbedtls_mpi_read_binary(&ecdh_ctx.Qp.Y, y, SECP256R1_PUBLIC_KEY_Y_SIZE);
    mbedtls_mpi_lset(&ecdh_ctx.Qp.Z, 1);
    mbedtls_ecdh_calc_secret(&ecdh_ctx, &size, shared_secret, SECP256R1_SHARED_SECRET_SIZE, device_mbedtls_rng, NULL);
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
