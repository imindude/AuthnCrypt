/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#ifndef APP_PINIF_H
#define APP_PINIF_H

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

void    pinif_init(void);
void    pinif_reset(void);
bool    pinif_postman(uint32_t cid, uint8_t *dat, uint16_t len, uint32_t now_ms);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* APP_PINIF_H */

/* end of file ****************************************************************************************************** */