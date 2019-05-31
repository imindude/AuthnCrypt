/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        FIDO definition
 * *********************************************************************************************************************
 */

#pragma once

/* ****************************************************************************************************************** */

#include <stdint.h>
#include <stdbool.h>

/* ****************************************************************************************************************** */

/**
 * capabilities
 */

#define FIDO_CAPABILITY_WINK        0x01
#define FIDO_CAPABILITY_CBOR        0x04
#define FIDO_CAPABILITY_NMSG        0x08
#define FIDO_CAPABILITIES           (FIDO_CAPABILITY_WINK | FIDO_CAPABILITY_CBOR)

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

#define CTAP1_REGISTER                      0x01
#define CTAP1_AUTHENTICATE                  0x02
#define CTAP1_VERSION                       0x03
// vendor command (0x40 ~ 0xBF)

#define CTAP1_VERSION_STR                   "U2F_V2"
#define CTAP1_APPL_PARAM_SIZE               32
#define CTAP1_CHAL_PARAM_SIZE               32
#define CTAP1_KEY_SIZE                      32
#define CTAP1_TAG_SIZE                      32
#define CTAP1_KEY_HANDLE_SIZE               (CTAP1_KEY_SIZE + CTAP1_TAG_SIZE)

/**
 * Status code
 */

#define FIDO_SW_NO_ERROR                    0x9000
#define FIDO_SW_CONDITINOS_NOT_SATISFIED    0x6985
#define FIDO_SW_WRONG_DATA                  0x6A80
#define FIDO_SW_WRONG_LENGTH                0x6700
#define FIDO_SW_CLA_NOT_SUPPORTED           0x6E00
#define FIDO_SW_INS_NOT_SUPPORTED           0x6D00

/**
 * Authenticate operation code
 */

#define CHECK_ONLY                              0x07
#define ENFORCE_USER_PRESENCE_AND_SIGN          0x03
#define DONT_ENFORCE_USER_PRESENCE_AND_SIGN     0x08

#define CTAP2_VERSION_STR                   "FIDO_2_0"

/* ****************************************************************************************************************** */

/**
 * FIDO Authenticator command
 */

#define authenticatorMakeCredential         0x01
#define authenticatorGetAssertion           0x02
#define authenticatorGetInfo                0x04
#define authenticatorClientPIN              0x06
#define authenticatorReset                  0x07
#define authenticatorGetNextAssertion       0x08
// vendor command
#define authenticatorVendorFirst            0x40
#define authenticatorVendorLast             0xBF

/**
 * authenticatorMakeCredential parameters
 */
#define MakeCredential_clientDataHash           0x01    // required / Byte Array
#define MakeCredential_rp                       0x02    // required / PublicKeyCredentialRpEntity
#define MakeCredential_user                     0x03    // required / PublicKeyCredentialUserEntity
#define MakeCredential_pubKeyCredParams         0x04    // required / CBOR Array
#define MakeCredential_excludeList              0x05    // optional / Sequence of PublicKeyCredentialDescriptors
#define MakeCredential_extensions               0x06    // optional / CBOR map of extension identifier
#define MakeCredential_options                  0x07    // optional / Map of authenticator options
#define MakeCredential_pinAuth                  0x08    // optional / Byte Array
#define MakeCredential_pinProtocol              0x09    // optional / Unsigned Integer

#define MakeCredentialResp_authData             0x01    // required / Byte Array
#define MakeCredentialResp_fmt                  0x02    // required / String
#define MakeCredentialResp_attStmt              0x03    // required / Byte Array

/**
 * authenticatorGetAssertion parameters
 */

#define GetAssertion_rpId                       0x01    // required / String
#define GetAssertion_clientDataHash             0x02    // required / Byte Array
#define GetAssertion_allowList                  0x03    // optional / Sequence of PublicKeyCredentialDescriptors
#define GetAssertion_extensions                 0x04    // optional / CBOR map of extension identifier
#define GetAssertion_options                    0x05    // optional / Map of authenticator options
#define GetAssertion_pinAuth                    0x06    // optional / Byte Array
#define GetAssertion_pinProtocol                0x07    // optional / Unsigned Integer

#define GetAssertionResp_credential             0x01    // optional / PublicKeyCredentialDescriptor
#define GetAssertionResp_authData               0x02    // required / Byte Array
#define GetAssertionResp_signature              0x03    // required / Byte Array
#define GetAssertionResp_user                   0x04    // optional / PublicKeyCredentialUserEntity
#define GetAssertionResp_numberOfCredentials    0x05    // optional / Integer

/**
 * authenticatorGetInfo of Response
 */

#define GetInfoResp_versions                    0x01    // required / Sequence of strings
#define GetInfoResp_extensions                  0x02    // optional / Sequence of strings
#define GetInfoResp_aaguid                      0x03    // required / Byte String
#define GetInfoResp_options                     0x04    // optional / Map
#define GetInfoResp_maxMsgSize                  0x05    // optional / Unsigned Integer
#define GetInfoResp_pinProtocols                0x06    // optional / Array of Unsigned Integer

/**
 * authenticatorClientPIN
 */

#define ClientPIN_pinProtocol                   0x01    // required / Unsigned Integer
#define ClientPIN_subCommand                    0x02    // required / Unsigned Integer
#define ClientPIN_keyAgreement                  0x03    // optional / COSE_Key
#define ClientPIN_pinAuth                       0x04    // Optional / Byte Array
#define ClientPIN_newPinEnc                     0x05    // Optional / Byte Array
#define ClientPIN_pinHashEnc                    0x06    // Optional / Byte Array

#define ClientPIN_SubCommand_getRetries         0x01
#define ClientPIN_SubCommand_getKeyAgreement    0x02
#define ClientPIN_SubCommand_setPIN             0x03
#define ClientPIN_SubCommand_changePIN          0x04
#define ClientPIN_SubCommand_getPINToken        0x05

#define ClientPIN_Resp_keyAgreement             0x01    // Optional / COSE_Key
#define ClientPIN_Resp_pinToken                 0x02    // Optional / COSE_Key
#define ClientPIN_Resp_retries                  0x03    // Optional / Unsigned Integer

/**
 * FIDO2
 */

#define FIDO2_PIN_PROTOCOL_VER              1
#define FIDO2_MAX_MSG_SIZE                  1200

/* ****************************************************************************************************************** */

/**
 * PublicKeyCredentialType
 */

#define CREDENTIAL_TYPE_PUBLIC_KEY_STR      "public-key"

/**
 * COSE key type (RFC-8152)
 */

#define COSE_Key_OKP                1
#define COSE_Key_EC2                2
#define COSE_Key_Symmetric          4

/**
 * COSE key label & value parameters (RFC-8152)
 */

#define COSE_Label_kty              1   // identification of the key type
#define COSE_Label_alg              3   // key usage restriction to this algorithm
#define COSE_Label_crv              -1  // EC identifier
#define COSE_Label_x                -2  // x-coordinate
#define COSE_Label_y                -3  // y-coordinate
#define COSE_Label_d                -4  // private key

// https://datatracker.ietf.org/doc/rfc8152/?include_text=1
#define COSE_Crv_P256               1

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
#define COSE_Alg_ES256              -7  // ECDSA w/ SHA256
#define COSE_Alg_HKDF256            -25 // ECDH-ES + HKDF-256

/**
 * attestation statement format identifier
 */

#define ATTESTATION_STATEMENT_FORMAT_IDENTIFIER     "packed"


/**
 * Credential type (custom)
 */

#define CREDENTIAL_TYPE_unknown             0
#define CREDENTIAL_TYPE_publicKey           1

/**
 * Extensions
 */

#define EXTENSIONS_TYPE_HMAC_SECRET_STR             "hmac-secret"

#define EXTENSIONS_HmacSecret_keyAgreement          0x01
#define EXTENSIONS_HmacSecret_saltEnc               0x02
#define EXTENSIONS_HmacSecret_saltAuth              0x03

/* ****************************************************************************************************************** */

#pragma pack(push, 1)

// https://www.w3.org/TR/webauthn/#credential-id
union CredentialId
{
    struct
    {
        uint8_t     tag_[16];
        union
        {
            struct
            {
                uint8_t     nonce_[32];
                uint32_t    count_;
            };
            uint8_t         seed_[32 + 4];
        };
    };
    uint8_t         bytes_[1];
};
typedef union CredentialId              CredentialId;

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialparameters
struct CredentialParameters
{
    int8_t      type_;                  // PublicKeyCredentialType (currently only "public-key")
    int32_t     alg_;                   // cryptographic algorithm
};
typedef struct CredentialParameters     CredentialParameters;

struct CredentialParametersList
{
    CredentialParameters    params_[10];
    int8_t      count_;
};
typedef struct CredentialParametersList CredentialParametersList;

// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
struct CredentialDescriptor
{
    int8_t          type_;              // PublicKeyCredentialType (currently only "public-key")
    CredentialId    id_;
};
typedef struct CredentialDescriptor     CredentialDescriptor;

struct CredentialDescriptorList
{
    CredentialDescriptor    descs_[10];
    int8_t      count_;
};
typedef struct CredentialDescriptorList CredentialDescriptorList;

struct CredentialUserEntity
{
    uint8_t     id_[128];               // BufferSource
    uint8_t     disp_name_[256];        // DOMString
};
typedef struct CredentialUserEntity     CredentialUserEntity;

struct CoseKey
{
    int         kty_;                   // COSE key type
    int         alg_;                   // COSE algorithm
    int         crv_;                   // EC identifier
    uint8_t     x_[32];                 // x-coordinate
    uint8_t     y_[32];                 // y-coordinate
    uint8_t     d_[32];                 // private key
};
typedef struct CoseKey                  CoseKey;

struct SaltEnc
{
    union
    {
        struct
        {
            uint8_t salt1_[32];
            uint8_t salt2_[32];
        };
        uint8_t     salt_[64];
    };
    int8_t      size_;
};
typedef struct SaltEnc                  SaltEnc;

struct SaltAuth
{
    uint8_t     auth_[16];
};
typedef struct SaltAuth                 SaltAuth;

struct HmacSecret
{
    CoseKey     key_agreement_;
    SaltEnc     salt_enc_;
    SaltAuth    salt_auth_;
};
typedef struct HmacSecret               HmacSecret;

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
struct ClientDataHashEntity
{
    uint8_t     hash_[32];              // Byte Array
};
typedef struct ClientDataHashEntity     ClientDataHashEntity;

// https://www.w3.org/TR/webauthn/#sctn-user-credential-params
struct UserEntity
{
    uint8_t     id_[128];               // BufferSource
    uint8_t     disp_name_[256];        // DOMString
};
typedef struct UserEntity               UserEntity;

struct Credential
{
    CredentialDescriptor    desc_;
    CredentialUserEntity    user_;
};
typedef struct Credential               Credential;

struct CredentialList
{
    Credential  credentials_[20];
    int8_t      count_;
};
typedef struct CredentialList           CredentialList;

struct ExtensionsEntity
{
    enum
    {
        _Extensions_None,
        _HmacSecret_Create,
        _HmacSecret_Get
    }
    type_;
    HmacSecret  secret_;
};
typedef struct ExtensionsEntity         ExtensionsEntity;

struct OptionsEntity
{
    bool        rk_;        // makeCredential
    bool        up_;        // getAssertion
    bool        uv_;        // makeCredential & getAssertion
};
typedef struct OptionsEntity            OptionsEntity;

struct PinAuthEntity
{
    uint8_t     auth_[16];
};
typedef struct PinAuthEntity            PinAuthEntity;

struct PinProtocolEntity
{
    uint32_t    version_;
};
typedef struct PinProtocolEntity        PinProtocolEntity;

struct SubCommandEntity
{
    uint32_t    command_;
};
typedef struct SubCommandEntity     SubCommandEntity;

struct KeyAgreementEntity
{
    CoseKey     key_;
};
typedef struct KeyAgreementEntity   KeyAgreementEntity;

struct NewPinEncEntity
{
    uint8_t     enc_[256];
    int16_t     len_;
};
typedef struct NewPinEncEntity      NewPinEncEntity;

struct PinHashEncEntity
{
    uint8_t     enc_[16];
    int16_t     len_;
};
typedef struct PinHashEncEntity     PinHashEncEntity;

// https://www.w3.org/TR/webauthn/#sctn-rp-credential-params
struct RelyingPartyId
{
    uint8_t     id_[256];               // DOMString
};
typedef struct RelyingPartyId       RelyingPartyId;

struct RelyingPartyEntity
{
    RelyingPartyId  id_;
};
typedef struct RelyingPartyEntity   RelyingPartyEntity;

struct MakeCredential
{
    ClientDataHashEntity        client_data_hash_;
    RelyingPartyEntity          relying_party_;
    UserEntity                  user_;
    CredentialParametersList    cred_param_list_;
    CredentialDescriptorList    exclude_list_;
    ExtensionsEntity            extensions_;
    OptionsEntity               options_;
    PinAuthEntity               pin_auth_;
    PinProtocolEntity           pin_protocol_;

    uint16_t    params_;
};
typedef struct MakeCredential       MakeCredential;

struct GetAssertion
{
    RelyingPartyId              rp_id_;
    ClientDataHashEntity        client_data_hash_;
    CredentialDescriptorList    allow_list_;
    ExtensionsEntity            extensions_;
    OptionsEntity               options_;
    PinAuthEntity               pin_auth_;
    PinProtocolEntity           pin_protocol_;

    uint16_t    params_;
};
typedef struct GetAssertion         GetAssertion;

struct ClientPin
{
    PinProtocolEntity       pin_protocol_;          // shall be 1
    SubCommandEntity        sub_command_;
    KeyAgreementEntity      key_agreement_;
    PinAuthEntity           pin_auth_;
    NewPinEncEntity         new_pin_enc_;
    PinHashEncEntity        pin_hash_enc_;

    uint16_t    params_;
};
typedef struct ClientPin            ClientPin;

#pragma pack(pop)

/* end of file ****************************************************************************************************** */
