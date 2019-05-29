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

#define SECP256R1_PRIVATE_KEY_SIZE          32
#define SECP256R1_PUBLIC_KEY_X_SIZE         32
#define SECP256R1_PUBLIC_KEY_Y_SIZE         32
#define SECP256R1_PUBLIC_KEY_SIZE           (SECP256R1_PUBLIC_KEY_X_SIZE + SECP256R1_PUBLIC_KEY_Y_SIZE)
#define SECP256R1_SHARED_SECRET_SIZE        32

#define FIDO_SIGNDER_MAX_SIZE               80

/* ****************************************************************************************************************** */

void    make_fido_tag(uint8_t *param, int16_t param_len, uint8_t *nonce, int16_t nonce_len, uint8_t *tag);
uint8_t make_attestation_sign(uint8_t *data, uint16_t data_size, uint8_t *sign_der);
void    make_secp256r1_private_key(uint8_t *param, int16_t param_len, uint8_t *private_key);
void    make_secp256r1_public_key(uint8_t *private_key, uint8_t *x, uint8_t *y);
void    get_authenticator_secret(uint8_t *x, uint8_t *y, uint8_t *shared_secret);
int32_t check_array_empty(uint8_t *array, uint32_t len);

/* end of file ****************************************************************************************************** */
