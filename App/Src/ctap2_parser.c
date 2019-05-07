/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "ctap2_parser.h"

/* ****************************************************************************************************************** */

static uint8_t bytestring_parser(CborValue *value, uint8_t *params, size_t *size)
{
    size_t  actual_size;

    if (cbor_value_get_type(value) != CborByteStringType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_string_length(value, &actual_size) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    if ((actual_size > 0) && (params != NULL))
    {
        if (cbor_value_copy_byte_string(value, params, size, NULL) != CborNoError)
            return FIDO_ERR_LIMIT_EXCEEDED;
    }
    else
    {
        *size = actual_size;
    }

    return FIDO_ERR_SUCCESS;
}

static uint8_t textstring_parser(CborValue *value, char *params, size_t *size)
{
    size_t  actual_size;

    if (cbor_value_get_type(value) != CborTextStringType)
        return  FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_string_length(value, &actual_size) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    if ((actual_size > 0) && (params != NULL))
    {
        if (cbor_value_copy_text_string(value, params, size, NULL) != CborNoError)
            return FIDO_ERR_LIMIT_EXCEEDED;
    }
    else
    {
        *size = actual_size;
    }

    return FIDO_ERR_SUCCESS;
}

static uint8_t integer_parser(CborValue *value, int *params)
{
    if (cbor_value_get_type(value) != CborIntegerType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_int_checked(value, params) != CborNoError)
        return FIDO_ERR_LIMIT_EXCEEDED;
    return FIDO_ERR_SUCCESS;
}

static uint8_t boolean_parser(CborValue *value, bool *params)
{
    if (cbor_value_get_type(value) != CborBooleanType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_boolean(value, params) != CborNoError)
        return FIDO_ERR_LIMIT_EXCEEDED;
    return FIDO_ERR_SUCCESS;
}

static uint8_t get_credential_type(char *type)
{
    return (strncmp(type, CREDENTIAL_TYPE_PUBLIC_KEY_STRING, strlen(CREDENTIAL_TYPE_PUBLIC_KEY_STRING)) == 0) ?
            CREDENTIAL_TYPE_Public_Key : CREDENTIAL_TYPE_Unknown;
}

static uint8_t get_credential_descriptor_list(CborValue *value, CborCredentialList *list)
{
    if (cbor_value_get_type(value) != CborArrayType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_enter_container(value, &list->value_) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_array_length(value, &list->count_) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;
    return FIDO_ERR_SUCCESS;
}

static uint8_t cose_key_parser(CborValue *value, CoseKey *cose)
{
    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_INVALID_CBOR;

    CborValue   map;
    size_t      map_size;
    uint8_t     result = FIDO_ERR_SUCCESS;

    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    do
    {
        int     key;
        size_t  size;

        if (cbor_value_get_map_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }
        if (cbor_value_get_int_checked(&map, &key) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }
        if (cbor_value_advance(&map) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        for (uint32_t i = 0; (result == FIDO_ERR_SUCCESS) && (i < map_size); i++)
        {
            switch (key)
            {
            case COSE_Label_kty:
                result = integer_parser(&map, &cose->kty_);
                break;
            case COSE_Label_alg:
                result = integer_parser(&map, &cose->alg_);
                break;
            case COSE_Label_crv:
                result = integer_parser(&map, &cose->crv_);
                break;
            case COSE_Label_x:
                size = sizeof(cose->x_);
                result = bytestring_parser(&map, cose->x_, &size);
                break;
            case COSE_Label_y:
                size = sizeof(cose->y_);
                result = bytestring_parser(&map, cose->y_, &size);
                break;
            case COSE_Label_d:
                size = sizeof(cose->d_);
                result = bytestring_parser(&map, cose->d_, &size);
                break;
            }

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }
        }
    }
    while (0);

    cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t hmac_secret_parser(CborValue *value, HmacSecret *secret)
{
    CborValue   map;
    size_t      map_size;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    uint8_t     result = FIDO_ERR_SUCCESS;

    do
    {
        if (cbor_value_get_map_length(val, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        for (uint32_t i = 0; (result == FIDO_ERR_SUCCESS) && (i < map_size); i++)
        {
            int     key;
            size_t  size;

            if (cbor_value_get_type(&map) != CborIntegerType)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }
            if (cbor_value_get_int_checked(&map, &key) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }
            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }

            switch (key)
            {
            case EXTENSIONS_HMAC_SECRET_KEY_AGREEMENT:

                result = cose_key_parser(&secret->cose_key_);
                break;

            case EXTENSIONS_HMAC_SECRET_SALT_ENC:

                size = sizeof(secret->salt_enc_);
                if (textstring_parser(&map, secret->salt_enc_, &size) == FIDO_ERR_SUCCESS)
                {
                    if (size == 64)
                        secret->is_two_salt_ = true;
                    else if (size == 32)
                        secret->is_two_salt_ = false;
                    else
                        result = FIDO_ERR_INVALID_LENGTH;
                }
                break;

            case EXTENSIONS_HMAC_SECRET_SALT_AUTH:

                size = sizeof(secret->salt_auth_);
                if (bytestring_parser(&map, secret->salt_auth_, &size) == FIDO_ERR_SUCCESS)
                {
                    if (size != 32)
                        result = FIDO_ERR_INVALID_LENGTH;
                }
                break;
            }
        }
    }
    while (0);

    return result;
}

static uint8_t pubkey_credparam_parser(CborValue *value, PubKeyCredParamsEntity *entity)
{
    CborValue   type_cbor;
    CborValue   alg_cbor;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    if ((cbor_value_map_find_value(value, "type", &type_cbor) != CborNoError) ||
            (cbor_value_get_type(&type_cbor) != CborTextStringType))
        return FIDO_ERR_INVALID_CBOR;
    if ((cbor_value_map_find_value(value, "alg", &alg_cbor) != CborNoError) ||
            (cbor_value_get_type(&alg_cbor) != CborTextStringType))
        return FIDO_ERR_INVALID_CBOR;

    char        type[16] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
    };
    int         cose;
    uint8_t     result;

    result = fido_cbor_textstring_parser(&type_cbor, type, sizeof(type));
    if (result != FIDO_ERR_SUCCESS)
        return result;
    result = fido_cbor_integer_parser(&alg_cbor, &cose);
    if (result != FIDO_ERR_SUCCESS)
        return result;

    memset(entity, 0, sizeof(PubKeyCredParamsEntity));

    entity->type_ = fido_get_credential_type(text);
    entity->cose_ = cose;

    return result;
}

static uint8_t get_extensions(CborValue *value, ExtensionsEntity *entity)
{
    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_INVALID_CBOR;

    CborValue   map;
    uint8_t     result = FIDO_ERR_SUCCESS;

    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    do
    {
        size_t      map_size;

        if (cbor_value_get_map_length(&map, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        for (uint32_t i = 0; i < map_size; i++)
        {
            char    key[16] = {
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0
            };

            result = textstring_parser(&map, key, sizeof(key));
            if (result != FIDO_ERR_SUCCESS)
                continue;

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                continue;
            }

            if (strncmp(key, "hmac-secret", 11) == 0)
            {
                CborType    type = cbor_value_get_type(&map);

                if (type == CborBooleanType)
                {
                    bool    hmac_create;

                    if (cbor_value_get_boolean(&map, &hmac_create) != CborNoError)
                    {
                        result = FIDO_ERR_INVALID_CBOR;
                        break;
                    }

                    entity->hmac_request_ = hmac_create ? _HmacSecretCreate : _HmacSecretNone;
                }
                else if (type == CborMapType)
                {
                    result = hmac_secret_parser(&map, &entity->hmac_secret_);
                    entity->hmac_request_ = (result == FIDO_ERR_SUCCESS) ? _HmacSecretGet : _HmacSecretNone;
                }
            }

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                continue;
            }
        }
    }
    while (0);

    cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t get_options(CborValue *value, OptionsEntity *options)
{
    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_INVALID_CBOR;

    CborValue   map;
    size_t      map_size;
    uint8_t     result = FIDO_ERR_SUCCESS;

    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    do
    {
        char    key[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        bool    b;
        size_t  size = sizeof(key);

        if (cbor_value_get_map_length(&map, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }
        if (textstring_parser(&map, key, &size) != FIDO_ERR_SUCCESS)
            break;
        if (cbor_value_advance(&map) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }
        if (boolean_parser(&map, &b) != FIDO_ERR_SUCCESS)
            break;
        if (cbor_value_advance(&map) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        if (strncmp(key, "rk", 2) == 0)
            options->rk_ = b;
        else if (strncmp(key, "up", 2) == 0)
            options->up_ = b;
        else if (strncmp(key, "uv", 2) == 0)
            options->uv_ = b;
    }
    while (0);

    cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t parser_make_credential_client_data_hash(CborValue *value, ClientDataHashEntity *entity)
{
    size_t  size = sizeof(entity->hash_);

    memset(entity, 0, sizeof(ClientDataHashEntity));
    return bytestring_parser(value, entity->hash_, &size);
}

static uint8_t parser_make_credential_rp(CborValue *value, RelyingPartyEntity *entity)
{
    CborValue   map;
    size_t      map_size;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    uint8_t     result = FIDO_ERR_SUCCESS;

    do
    {
        if (cbor_value_get_map_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        memset(entity, 0, sizeof(RelyingPartyEntity));

        for (uint32_t i = 0; (result == FIDO_ERR_SUCCESS) && (i < map_size); i++)
        {
            char    key[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
            size_t  size = sizeof(key);

            result = textstring_parser(&map, key, &size);
            if (result != FIDO_ERR_SUCCESS)
                continue;

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                continue;
            }

            if (strncmp(key, "id", 2) == 0)
            {
                size = sizeof(entity->id_);
                result = textstring_parser(&map, entity->id_, &size);
                if (result != FIDO_ERR_SUCCESS)
                    continue;
            }

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                continue;
            }
        }
    }
    while (0);

    cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t parser_make_credential_user(CborValue *value, UserEntity *entity)
{
    CborValue   map;
    size_t      map_size;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    uint8_t     result = FIDO_ERR_SUCCESS;

    do
    {
        if (cbor_value_get_map_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        memset(entity, 0, sizeof(UserEntity));

        for (uint32_t i = 0; (res == FIDO_ERR_SUCCESS) && (i < map_size); i++)
        {
            char    key[24] = {
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0
            };
            size_t  size = sizeof(key);

            result = textstring_parser(&map, key, &size);
            if (result != FIDO_ERR_SUCCESS)
                continue;

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                continue;
            }

            if (strncmp(key, "id", 2) == 0)
            {
                size = sizeof(entity->id_);
                result = textstring_parser(&map, entity->id_, &size);
                if (result != FIDO_ERR_SUCCESS)
                    continue;
            }
            else if (strncmp(key, "displayName", 11) == 0)
            {
                size = sizeof(entity->disp_name_);
                result = textstring_parser(&map, entity->disp_name_, &size);
                if (result != FIDO_ERR_SUCCESS)
                    continue;
            }

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                continue;
            }
        }
    }
    while (0);

    cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t parser_make_credential_pubkey_cred_params(CborValue *value, PubKeyCredParamsEntity *entity)
{
    CborValue   map;

    if (cbor_value_get_type(value) != CborArrayType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    size_t      map_size;
    uint8_t     result = FIDO_ERR_SUCCESS;

    do
    {
        if (cbor_value_get_map_length(&map, map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        memset(entity, 0, sizeof(PubKeyCredParamsEntity));

        for (uint32_t i = 0; (result == FIDO_ERR_SUCCESS) && (i < map_size); i++)
        {
            if (pubkey_credparam_parser(&map, entity) != FIDO_ERR_SUCCESS)
                continue;

            if ((entity->type_ == CREDENTIAL_TYPE_Public_Key) && (entity->cose_ == COSE_Value_ES256))
                break;

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }
        }
    }
    while (0);

    cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t parser_make_credential_exclude_list(CborValue *value, CborCredentialList *exclude_list)
{
    memset(exclude_list, 0, sizeof(CborCredentialList));
    return get_credential_descriptor_list(value, exclude_list);
}

static uint8_t parser_make_credential_extensions(CborValue *value, ExtensionsEntity *entity)
{
    memset(entity, 0, sizeof(ExtensionsEntity));
    return get_extensions(value, entity);
}

static uint8_t parser_make_credential_options(CborValue *value, OptionsEntity *entity)
{
    memset(entity, 0, sizeof(OptionsEntity));
    return get_options(value, entity);
}

static uint8_t parser_make_credential_pin_auth(CborValue *value, PinAuthEntity *entity)
{
    memset(entity, 0, sizeof(PinAuthEntity));

    size_t  size = sizeof(entity->pin_);
    uint8_t result = bytestring_parser(value, entity->pin_, &size);

    if (result == FIDO_ERR_SUCCESS)
    {
        if (size == 0)
            entity->zero_pin_ = true;
        else
            entity->presence_ = true;
    }

    return result;
}

static uint8_t parser_make_credential_pin_protocol(CborValue *value, PinProtocolEntity *entity)
{
    memset(entity, 0, sizeof(PinProtocolEntity));

    int     version;
    uint8_t result = integer_parser(value, &version);

    if (result == FIDO_ERR_SUCCESS)
        entity->version_ = (uint32_t)version;

    return result;
}

uint8_t ctap2_parser_make_credential(uint8_t *dat, uint16_t len, MakeCredential *make_cred,
        CborCredentialList *exclude_list)
{
    CborParser  parser;
    CborValue   iter, map;

    if (cbor_parser_init(dat, len, CborValidateCanonicalFormat, &parser, &iter) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_type(&it) != CborMapType)
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    if (cbor_value_enter_container(&iter, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    size_t      map_size;
    uint8_t     result = FIDO_ERR_SUCCESS;

    do
    {
        if (cbor_value_get_map_length(&iter, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        for (uint32_t i = 0; (result == FIDO_ERR_SUCCESS) && (i < map_size); i++)
        {
            int32_t key;

            if (cbor_value_get_type(&map) != CborIntegerType)
            {
                result = FIDO_ERR_CBOR_UNEXPECTED_TYPE;
                break;
            }
            if (cbor_value_get_int_checked(&map, &key) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }
            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }

            switch (key)
            {
            case MakeCredential_clientDataHash:
                result = parser_make_credential_client_data_hash(&map, &make_cred->client_data_hash_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_clientDataHash;
                break;
            case MakeCredential_rp:
                result = parser_make_credential_rp(&map, &make_cred->relying_party_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_rp;
                break;
            case MakeCredential_user:
                result = parser_make_credential_user(&map, &make_cred->user_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_user;
                break;
            case MakeCredential_pubKeyCredParams:
                result = parser_make_credential_pubkey_cred_params(&map, &make_cred->pubkey_cred_param_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_pubKeyCredParams;
                break;
            case MakeCredential_excludeList:
                result = parser_make_credential_exclude_list(&map, &exclude_list);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_excludeList;
                break;
            case MakeCredential_extensions:
                result = parser_make_credential_extensions(&map, &make_cred->extensions_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_extensions;
                break;
            case MakeCredential_options:
                result = parser_make_credential_options(&map, &make_cred->options_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_options;
                break;
            case MakeCredential_pinAuth:
                result = parser_make_credential_pin_auth(&map, &make_cred->pin_auth_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_pinAuth;
                break;
            case MakeCredential_pinProtocol:
                result = parser_make_credential_pin_protocol(&map, &make_cred->pin_protocol_);
                if (result == FIDO_ERR_SUCCESS)
                    make_cred->params_ |= MakeCredentialParam_pinProtocol;
                break;
            default:
                // options not yet
                break;
            }

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }
        }
    }
    while (0);

    cbor_value_leave_container(&iter, &map);

    return result;
}

uint8_t ctap2_parser_credential_descriptor(CborValue *value, CredentialDesc *descriptor)
{
    CborValue   map;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_map_find_value(value, "id", &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    size_t  size = sizeof(descriptor->credential_.custom_);
    uint8_t result = bytestring_parser(&map, &descriptor->credential_.custom_, &size);

    if (result != FIDO_ERR_SUCCESS)
        return result;

    if (size == CTAP1_KEY_HANDLE_SIZE)
        descriptor->type_ = CREDENTIAL_TYPE_CTAP1;

    if (cbor_value_map_find_value(value, "type", &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    char    key[16] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
    };

    size = sizeof(key);
    result = textstring_parser(&map, key, &size);
    if (result != FIDO_ERR_SUCCESS)
        return result;

    if (get_credential_type(key) == CREDENTIAL_TYPE_Public_Key)
    {
        if (descriptor->type_ == CREDENTIAL_TYPE_Unknown)
            descriptor->type_ = CREDENTIAL_TYPE_Public_Key;
    }

    return FIDO_ERR_SUCCESS;
}

/* end of file ****************************************************************************************************** */
