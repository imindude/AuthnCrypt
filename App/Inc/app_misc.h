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

void    make_ctap1_tag(uint8_t *param, int16_t param_len, uint8_t *key, int16_t key_len, uint8_t *tag);
void    make_ctap2_tag(uint8_t *param, int16_t param_len, uint8_t *seed, int16_t seed_len, uint32_t count, uint8_t *tag);

/* end of file ****************************************************************************************************** */
