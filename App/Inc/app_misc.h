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

void    make_fido_tag(uint8_t *param, int16_t param_len, uint8_t *nonce, int16_t nonce_len, uint8_t *tag);
bool    check_array_empty(uint8_t *array, uint32_t len);

/* end of file ****************************************************************************************************** */
