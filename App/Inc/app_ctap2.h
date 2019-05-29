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

void    ctap2_init(void);
void    ctap2_reset(void);
void    ctap2_postman(uint32_t cid, uint8_t *dat, uint16_t len, uint32_t now_ms);

/* end of file ****************************************************************************************************** */
