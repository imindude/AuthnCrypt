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
#include <stdint.h>

/* ****************************************************************************************************************** */

/* FIDO USBHID Protocol */
#define HIDIF_PROTOCOL_VERSION      2
#define HIDIF_INVALID_CID           0
#define HIDIF_BROADCAST_CID         0xFFFFFFFF

/* FIDO USBHID Command */
#define HIDIF_PING                  0x01
#define HIDIF_MSG                   0x03
#define HIDIF_LOCK                  0x04
#define HIDIF_INIT                  0x06
#define HIDIF_WINK                  0x08
#define HIDIF_CBOR                  0x10
#define HIDIF_CANCEL                0x11
#define HIDIF_KEEPALIVE             0x3B
#define HIDIF_ERROR                 0x3F
// vendor command (0x40~0x7F)
#define HIDIF_PIN                   0x54
#define HIDIF_CIPHER                0x55

/* ****************************************************************************************************************** */

void        hidif_init(void);
uint16_t    hidif_add_byte(uint8_t byte);
uint16_t    hidif_add_bytes(uint8_t *bytes, uint16_t size);
uint16_t    hidif_append_sw(uint16_t sw);
void        hidif_write(uint32_t cid, uint8_t cmd);
void        hidif_error(uint32_t cid, uint8_t code);

/* end of file ****************************************************************************************************** */
