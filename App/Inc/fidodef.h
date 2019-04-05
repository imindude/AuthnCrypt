/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        FIDO definition
 * *********************************************************************************************************************
 */

#ifndef FIDODEF_H
#define FIDODEF_H

/* ****************************************************************************************************************** */

/**
 * capabilities
 */

#define FIDO_CAPABILITY_WINK        0x01
#define FIDO_CAPABILITY_CBOR        0x04
#define FIDO_CAPABILITY_NMSG        0x08
#define FIDO_CAPABILITIES           (FIDO_CAPABILITY_WINK)// | FIDO_CAPABILITY_CBOR)

/**
 * KEEPALIVE command params
 */

#define KEEPALIVE_PROCESSING        0x01
#define KEEPALIVE_TUP_NEEDED        0x02

/**
 * FIDO error code
 */

#define FIDO_ERR_SUCCESS                    0x00
#define FIDO_ERR_INVALID_COMMAND            0x01
#define FIDO_ERR_INVALID_PARAMETER          0x02
#define FIDO_ERR_INVALID_LENGTH             0x03
#define FIDO_ERR_INVALID_SEQ                0x04
#define FIDO_ERR_TIMEOUT                    0x05
#define FIDO_ERR_CHANNEL_BUSY               0x06
#define FIDO_ERR_LOCK_REQUIRED              0x0A
#define FIDO_ERR_INVALID_CHANNEL            0x0B
#define FIDO_ERR_CBOR_UNEXPECTED_TYPE       0x11
#define FIDO_ERR_INVALID_CBOR               0x12
#define FIDO_ERR_MISSING_PARAMETER          0x14
#define FIDO_ERR_LIMIT_EXCEEDED             0x15
#define FIDO_ERR_UNSUPPORTED_EXTENSION      0x16
#define FIDO_ERR_CREDENTIAL_EXCLUDED        0x19
#define FIDO_ERR_PROCESSING                 0x21
#define FIDO_ERR_INVALID_CREDENTIAL         0x22
#define FIDO_ERR_USER_ACTION_PENDING        0x23
#define FIDO_ERR_OPERATION_PENDING          0x24
#define FIDO_ERR_NO_OPERATIONS              0x25
#define FIDO_ERR_UNSUPPORTED_ALGORITHM      0x26
#define FIDO_ERR_OPERATION_DENIED           0x27
#define FIDO_ERR_KEY_STORE_FULL             0x28
#define FIDO_ERR_NOT_BUSY                   0x29
#define FIDO_ERR_NO_OPERATION_PENDING       0x2A
#define FIDO_ERR_UNSUPPORTED_OPTION         0x2B
#define FIDO_ERR_INVALID_OPTION             0x2C
#define FIDO_ERR_KEEPALIVE_CANCEL           0x2D
#define FIDO_ERR_NO_CREDENTIALS             0x2E
#define FIDO_ERR_USER_ACTION_TIMEOUT        0x2F
#define FIDO_ERR_NOT_ALLOWED                0x30
#define FIDO_ERR_PIN_INVALID                0x31
#define FIDO_ERR_PIN_BLOCKED                0x32
#define FIDO_ERR_PIN_AUTH_INVALID           0x33
#define FIDO_ERR_PIN_AUTH_BLOCKED           0x34
#define FIDO_ERR_PIN_NOT_SET                0x35
#define FIDO_ERR_PIN_REQUIRED               0x36
#define FIDO_ERR_PIN_POLICY_VIOLATION       0x37
#define FIDO_ERR_PIN_TOKEN_EXPIRED          0x38
#define FIDO_ERR_REQUEST_TOO_LARGE          0x39
#define FIDO_ERR_ACTION_TIMEOUT             0x3A
#define FIDO_ERR_UP_REQUIRED                0x3B
#define FIDO_ERR_OTHER                      0x7F
#define FIDO_ERR_SPEC_LAST                  0xDF
#define FIDO_ERR_EXTENSION_FIRST            0xE0
#define FIDO_ERR_EXTENSION_LAST             0xEF
#define FIDO_ERR_VENDOR_FIRST               0xF0
#define FIDO_ERR_VENDOR_LAST                0xFF

/**
 * U2F command
 */

#define U2F_REGISTER                0x01
#define U2F_AUTHENTICATE            0x02
#define U2F_VERSION                 0x03
// vendor command (0x40 ~ 0xBF)

/**
 * Status code
 */

#define SW_NO_ERROR                     0x9000
#define SW_CONDITINOS_NOT_SATISFIED     0x6985
#define SW_WRONG_DATA                   0x6A80
#define SW_WRONG_LENGTH                 0x6700
#define SW_CLA_NOT_SUPPORTED            0x6E00
#define SW_INS_NOT_SUPPORTED            0x6D00

/**
 * Authenticate operation code
 */

#define CHECK_ONLY                              0x07
#define ENFORCE_USER_PRESENCE_AND_SIGN          0x03
#define DONT_ENFORCE_USER_PRESENCE_AND_SIGN     0x08

/**
 * FIDO Version
 */

#define U2F_VERSION_STR         "U2F_V2"

/* ****************************************************************************************************************** */

#endif  /* FIDODEF_H */

/* end of file ****************************************************************************************************** */
