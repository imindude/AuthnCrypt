/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#pragma once

/* ****************************************************************************************************************** */

#define VERSION_MAJOR       1
#define VERSION_MINOR       0
#ifdef RELEASE
#include "build_number.h"
#else
#define BUILD_NUMBER        1
#endif

/* ****************************************************************************************************************** */

#define PIN_CLASS                   0x54
#define PIN_INS_TOUCH               0x10
#define PIN_INS_CHECK               0x20
#define PIN_INS_GET                 0x21
#define PIN_INS_SET                 0x22

#define PIN_SW_NO_ERROR             0x9000
#define PIN_SW_VERIFY_FAILED        0x9004
#define PIN_SW_CONFIRM              0x9100
#define PIN_SW_KEEPALIVE            0x6984
#define PIN_SW_NOT_SATISFIED        0x6985
#define PIN_SW_TIMEOUT              0x6800
#define PIN_SW_WRONG_DATA           0x6A80
#define PIN_SW_INVALID_CLA          0x6E00
#define PIN_SW_INVALID_INS          0x6D00
#define PIN_SW_INVALID_PARAM        0x6C00
#define PIN_SW_ERR_OTHER            0x6F00

/* end of file ****************************************************************************************************** */
