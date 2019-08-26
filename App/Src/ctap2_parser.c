/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "ctap2_parser.h"
#include "cbor.h"

/* ****************************************************************************************************************** */

static int8_t get_credential_type(char *type_str)
{
    return (strncmp(CREDENTIAL_TYPE_PUBLIC_KEY_STR, type_str, strlen(CREDENTIAL_TYPE_PUBLIC_KEY_STR)) == 0) ?
            CREDENTIAL_TYPE_publicKey : CREDENTIAL_TYPE_unknown;
}

static uint8_t bytestring_parser(CborValue *value, uint8_t *params, size_t *size)
{
    size_t  actual_size;

    if (cbor_value_get_type(value) != CborByteStringType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_string_length(value, &actual_size) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    *size = actual_size;

    if ((actual_size > 0) && (params != NULL))
    {
        if (cbor_value_copy_byte_string(value, params, size, NULL) != CborNoError)
            return FIDO_ERR_LIMIT_EXCEEDED;
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

    *size = actual_size;

    if ((actual_size > 0) && (params != NULL))
    {
        if (cbor_value_copy_text_string(value, params, size, NULL) != CborNoError)
            return FIDO_ERR_LIMIT_EXCEEDED;
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

    if (result == FIDO_ERR_SUCCESS)
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
        if (cbor_value_get_map_length(value, &map_size) != CborNoError)
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
            case EXTENSIONS_HmacSecret_keyAgreement:

                result = cose_key_parser(&map, &secret->key_agreement_);
                break;

            case EXTENSIONS_HmacSecret_saltEnc:

                size = sizeof(secret->salt_enc_);
                result = bytestring_parser(&map, secret->salt_enc_.salt_, &size);
                if (result == FIDO_ERR_SUCCESS)
                {
                    if ((size == 32) || (size == 64))
                        secret->salt_enc_.size_ = size;
                    else
                        result = FIDO_ERR_INVALID_PARAMETER;
                }
                break;

            case EXTENSIONS_HmacSecret_saltAuth:

                size = sizeof(secret->salt_auth_.auth_);
                result = bytestring_parser(&map, secret->salt_auth_.auth_, &size);
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

    if (result == FIDO_ERR_SUCCESS)
        cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t pubkey_credparam_parser(CborValue *value, CredentialParameters *cred_param)
{
    CborValue   type_cbor;
    CborValue   alg_cbor;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    if ((cbor_value_map_find_value(value, "type", &type_cbor) != CborNoError) ||
            (cbor_value_get_type(&type_cbor) != CborTextStringType))
        return FIDO_ERR_INVALID_CBOR;
    if ((cbor_value_map_find_value(value, "alg", &alg_cbor) != CborNoError) ||
            (cbor_value_get_type(&alg_cbor) != CborIntegerType))
        return FIDO_ERR_INVALID_CBOR;

    char        type[16] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
    };
    size_t      size = sizeof(type);
    int         alg;
    uint8_t     result;

    result = textstring_parser(&type_cbor, type, &size);
    if (result != FIDO_ERR_SUCCESS)
        return result;
    result = integer_parser(&alg_cbor, &alg);
    if (result != FIDO_ERR_SUCCESS)
        return result;

    cred_param->type_ = get_credential_type(type);
    cred_param->alg_ = alg;

    return FIDO_ERR_SUCCESS;
}

static uint8_t pubkey_creddesc_parser(CborValue *value, CredentialDescriptor *cred_desc)
{
    CborValue   type_cbor;
    CborValue   id_cbor;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    if ((cbor_value_map_find_value(value, "type", &type_cbor) != CborNoError) ||
            (cbor_value_get_type(&type_cbor) != CborTextStringType))
        return FIDO_ERR_INVALID_CBOR;
    if ((cbor_value_map_find_value(value, "id", &id_cbor) != CborNoError) ||
            (cbor_value_get_type(&id_cbor) != CborByteStringType))
        return FIDO_ERR_INVALID_CBOR;

    uint8_t     result;
    char        type[16] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
    };
    size_t      size = sizeof(type);

    result = textstring_parser(&type_cbor, type, &size);
    if (result != FIDO_ERR_SUCCESS)
        return result;
    cred_desc->type_ = get_credential_type(type);

    size = sizeof(cred_desc->id_);
    result = bytestring_parser(&id_cbor, cred_desc->id_.bytes_, &size);

    return result;
}

static uint8_t get_extensions(CborValue *value, ExtensionsEntity *entity)
{
    CborValue   map;
    uint8_t     result = FIDO_ERR_SUCCESS;
    size_t      map_size;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    do
    {
        if (cbor_value_get_map_length(value, &map_size) != CborNoError)
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
            size_t  size = sizeof(key);

            result = textstring_parser(&map, key, &size);
            if (result != FIDO_ERR_SUCCESS)
                break;

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }

            if (strncmp(key, EXTENSIONS_TYPE_HMAC_SECRET_STR, strlen(EXTENSIONS_TYPE_HMAC_SECRET_STR)) == 0)
            {
                CborType    type = cbor_value_get_type(&map);

                if (type == CborBooleanType)
                {
                    bool    create = false;

                    if (cbor_value_get_boolean(&map, &create) != CborNoError)
                    {
                        result = FIDO_ERR_INVALID_CBOR;
                        break;
                    }
                    entity->type_ = _HmacSecret_Create;
                }
                else if (type == CborMapType)
                {
                    if ((result = hmac_secret_parser(&map, &entity->secret_)) != FIDO_ERR_SUCCESS)
                    {
                        result = FIDO_ERR_INVALID_CBOR;
                        break;
                    }
                    entity->type_ = _HmacSecret_Get;
                }
            }

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }
        }
    }
    while (0);

    if (result == FIDO_ERR_SUCCESS)
        cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t get_options(CborValue *value, OptionsEntity *options)
{
    CborValue   map;
    size_t      map_size;
    uint8_t     result = FIDO_ERR_SUCCESS;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    do
    {
        char    key[4] = { 0, 0, 0, 0 };
        bool    b;
        size_t  size = sizeof(key);

        if (cbor_value_get_map_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        for (uint32_t i = 0; i < map_size; i++)
        {
            if ((result = textstring_parser(&map, key, &size)) != FIDO_ERR_SUCCESS)
                break;
            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }

            if ((result = boolean_parser(&map, &b)) != FIDO_ERR_SUCCESS)
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
    }
    while (0);

    if (result == FIDO_ERR_SUCCESS)
        cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t parser_make_credential_client_data_hash(CborValue *value, ClientDataHashEntity *entity)
{
    size_t  size = sizeof(entity->hash_);
    uint8_t result = bytestring_parser(value, entity->hash_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_make_credential_rp(CborValue *value, RelyingPartyEntity *rp_entity)
{
    CborValue   map;
    size_t      map_size;
    uint8_t     result = FIDO_ERR_SUCCESS;

    if (cbor_value_get_type(value) != CborMapType)
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    if (cbor_value_enter_container(value, &map) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;

    do
    {
        if (cbor_value_get_map_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        for (uint32_t i = 0; i < map_size; i++)
        {
            char    key[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
            size_t  size = sizeof(key);

            result = textstring_parser(&map, key, &size);
            if (result != FIDO_ERR_SUCCESS)
                break;

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }

            if (strncmp(key, "id", 2) == 0)
            {
                size = sizeof(rp_entity->id_.id_);
                result = textstring_parser(&map, (char*)rp_entity->id_.id_, &size);
                if (result != FIDO_ERR_SUCCESS)
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

    if (result == FIDO_ERR_SUCCESS)
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

        for (uint32_t i = 0; (result == FIDO_ERR_SUCCESS) && (i < map_size); i++)
        {
            char    key[16] = {
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0
            };
            size_t  size = sizeof(key);

            result = textstring_parser(&map, key, &size);
            if (result != FIDO_ERR_SUCCESS)
                break;

            if (cbor_value_advance(&map) != CborNoError)
            {
                result = FIDO_ERR_INVALID_CBOR;
                break;
            }

            if (strncmp(key, "id", 2) == 0)
            {
                size = sizeof(entity->id_);
                result = bytestring_parser(&map, entity->id_, &size);
//                result = textstring_parser(&map, (char*)entity->id_, &size);
                if (result != FIDO_ERR_SUCCESS)
                    break;
            }
            else if (strncmp(key, "displayName", 11) == 0)
            {
                size = sizeof(entity->disp_name_);
                result = textstring_parser(&map, (char*)entity->disp_name_, &size);
                if (result != FIDO_ERR_SUCCESS)
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

    if (result == FIDO_ERR_SUCCESS)
        cbor_value_leave_container(value, &map);

    return result;
}

static uint8_t parser_make_credential_pubkey_cred_params(CborValue *value, CredentialParametersList *cred_param_list)
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
        if (cbor_value_get_array_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        int16_t     max_entities = sizeof(cred_param_list->params_) / sizeof(cred_param_list->params_[0]);

        for (uint32_t i = 0; (i < map_size) && (cred_param_list->count_ < max_entities); i++)
        {
            if ((result = pubkey_credparam_parser(&map, &cred_param_list->params_[cred_param_list->count_]))
                    == FIDO_ERR_SUCCESS)
                cred_param_list->count_++;
            else
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

static uint8_t parser_make_credential_exclude_list(CborValue *value, CredentialDescriptorList *cred_desc_list)
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
        if (cbor_value_get_array_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        int16_t     max_entities = sizeof(cred_desc_list->descs_) / sizeof(cred_desc_list->descs_[0]);

        for (uint32_t i = 0; (i < map_size) && (cred_desc_list->count_ < max_entities); i++)
        {
            if ((result = pubkey_creddesc_parser(&map, &cred_desc_list->descs_[cred_desc_list->count_])) ==
                    FIDO_ERR_SUCCESS)
                cred_desc_list->count_++;
            else
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

static uint8_t parser_make_credential_extensions(CborValue *value, ExtensionsEntity *entity)
{
    uint8_t result = get_extensions(value, entity);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_make_credential_options(CborValue *value, OptionsEntity *entity)
{
    uint8_t result = get_options(value, entity);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_make_credential_pin_auth(CborValue *value, PinAuthEntity *entity)
{
    size_t  size = sizeof(entity->auth_);
    uint8_t result = bytestring_parser(value, entity->auth_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_make_credential_pin_protocol(CborValue *value, PinProtocolEntity *entity)
{
    int     version;
    uint8_t result = integer_parser(value, &version);

    if (result == FIDO_ERR_SUCCESS)
        entity->version_ = (uint32_t)version;

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_get_assertion_rp_id(CborValue *value, RelyingPartyId *rpid)
{
    size_t  size = sizeof(rpid->id_);
    uint8_t result = textstring_parser(value, (char*)rpid->id_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_get_assertion_client_data_hash(CborValue *value, ClientDataHashEntity *entity)
{
    size_t  size = sizeof(entity->hash_);
    uint8_t result = bytestring_parser(value, entity->hash_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_get_assertion_allow_list(CborValue *value, CredentialDescriptorList *cred_desc_list)
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
        if (cbor_value_get_array_length(value, &map_size) != CborNoError)
        {
            result = FIDO_ERR_INVALID_CBOR;
            break;
        }

        int16_t     max_entities = sizeof(cred_desc_list->descs_) / sizeof(cred_desc_list->descs_[0]);

        for (uint32_t i = 0; (i < map_size) && (cred_desc_list->count_ < max_entities); i++)
        {
            if ((result = pubkey_creddesc_parser(&map, &cred_desc_list->descs_[cred_desc_list->count_])) ==
                    FIDO_ERR_SUCCESS)
                cred_desc_list->count_++;
            else
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

static uint8_t parser_get_assertion_extensions(CborValue *value, ExtensionsEntity *entity)
{
    uint8_t result = get_extensions(value, entity);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_get_assertion_options(CborValue *value, OptionsEntity *entity)
{
    uint8_t result = get_options(value, entity);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_get_assertion_pin_auth(CborValue *value, PinAuthEntity *entity)
{
    size_t  size = sizeof(entity->auth_);
    uint8_t result = bytestring_parser(value, entity->auth_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_get_assertion_pin_protocol(CborValue *value, PinProtocolEntity *entity)
{
    int     version;
    uint8_t result = integer_parser(value, &version);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;
    if (result == FIDO_ERR_SUCCESS)
        entity->version_ = (uint32_t)version;

    return result;
}

static uint8_t parser_client_pin_pin_protocol(CborValue *value, PinProtocolEntity *entity)
{
    int     version;
    uint8_t result = integer_parser(value, &version);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;
    if (result == FIDO_ERR_SUCCESS)
        entity->version_ = (uint32_t)version;

    return result;
}

static uint8_t parser_client_pin_sub_command(CborValue *value, SubCommandEntity *entity)
{
    int     command;
    uint8_t result = integer_parser(value, &command);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;
    if (result == FIDO_ERR_SUCCESS)
        entity->command_ = (uint32_t)command;

    return result;
}

static uint8_t parser_client_pin_key_agreement(CborValue *value, KeyAgreementEntity *entity)
{
    uint8_t result = cose_key_parser(value, &entity->key_);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_client_pin_pin_auth(CborValue *value, PinAuthEntity *entity)
{
    size_t  size = sizeof(entity->auth_);
    uint8_t result = bytestring_parser(value, entity->auth_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;

    return result;
}

static uint8_t parser_client_pin_new_pin_enc(CborValue *value, NewPinEncEntity *entity)
{
    size_t  size = sizeof(entity->enc_);
    uint8_t result = bytestring_parser(value, entity->enc_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;
    entity->len_ = size;

    return result;
}

static uint8_t parser_client_pin_pin_hash_enc(CborValue *value, PinHashEncEntity *entity)
{
    size_t  size = sizeof(entity->enc_);
    uint8_t result = bytestring_parser(value, entity->enc_, &size);

    if (cbor_value_advance(value) != CborNoError)
        result = FIDO_ERR_INVALID_CBOR;
    entity->len_ = size;

    return result;
}

uint8_t ctap2_parser_make_credential(uint8_t *dat, uint16_t len, MakeCredential *make_credential)
{
    CborParser  parser;
    CborValue   iter, map;

    if (cbor_parser_init(dat, len, CborValidateCanonicalFormat, &parser, &iter) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_type(&iter) != CborMapType)
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

        for (uint32_t i = 0; i < map_size; i++)
        {
            int     key;

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
                result = parser_make_credential_client_data_hash(&map, &make_credential->client_data_hash_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_clientDataHash;
                break;
            case MakeCredential_rp:
                result = parser_make_credential_rp(&map, &make_credential->relying_party_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_rp;
                break;
            case MakeCredential_user:
                result = parser_make_credential_user(&map, &make_credential->user_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_user;
                break;
            case MakeCredential_pubKeyCredParams:
                result = parser_make_credential_pubkey_cred_params(&map, &make_credential->cred_param_list_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_pubKeyCredParams;
                break;
            case MakeCredential_excludeList:
                result = parser_make_credential_exclude_list(&map, &make_credential->exclude_list_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_excludeList;
                break;
            case MakeCredential_extensions:
                result = parser_make_credential_extensions(&map, &make_credential->extensions_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_extensions;
                break;
            case MakeCredential_options:
                result = parser_make_credential_options(&map, &make_credential->options_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_options;
                break;
            case MakeCredential_pinAuth:
                result = parser_make_credential_pin_auth(&map, &make_credential->pin_auth_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_pinAuth;
                break;
            case MakeCredential_pinProtocol:
                result = parser_make_credential_pin_protocol(&map, &make_credential->pin_protocol_);
                if (result == FIDO_ERR_SUCCESS)
                    make_credential->params_ |= MakeCredentialParam_pinProtocol;
                break;
            default:
                if (cbor_value_advance(&map) != CborNoError)
                    result = FIDO_ERR_INVALID_CBOR;
                break;
            }
        }
    }
    while (0);

    if (result == FIDO_ERR_SUCCESS)
        cbor_value_leave_container(&iter, &map);

    return result;
}

uint8_t ctap2_parser_get_assertion(uint8_t *dat, uint16_t len, GetAssertion *get_assertion)
{
    CborParser  parser;
    CborValue   iter, map;

    if (cbor_parser_init(dat, len, CborValidateCanonicalFormat, &parser, &iter) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_type(&iter) != CborMapType)
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

        for (uint32_t i = 0; i < map_size; i++)
        {
            int     key;

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
            case GetAssertion_rpId:
                result = parser_get_assertion_rp_id(&map, &get_assertion->rp_id_);
                if (result == FIDO_ERR_SUCCESS)
                    get_assertion->params_ |= GetAssertionParam_rpId;
                break;
            case GetAssertion_clientDataHash:
                result = parser_get_assertion_client_data_hash(&map, &get_assertion->client_data_hash_);
                if (result == FIDO_ERR_SUCCESS)
                    get_assertion->params_ |= GetAssertionParam_clientDataHash;
                break;
            case GetAssertion_allowList:
                result = parser_get_assertion_allow_list(&map, &get_assertion->allow_list_);
                if (result == FIDO_ERR_SUCCESS)
                    get_assertion->params_ |= GetAssertionParam_allowList;
                break;
            case GetAssertion_extensions:
                result = parser_get_assertion_extensions(&map, &get_assertion->extensions_);
                if (result == FIDO_ERR_SUCCESS)
                    get_assertion->params_ |= GetAssertionParam_extensions;
                break;
            case GetAssertion_options:
                result = parser_get_assertion_options(&map, &get_assertion->options_);
                if (result == FIDO_ERR_SUCCESS)
                    get_assertion->params_ |= GetAssertionParam_options;
                break;
            case GetAssertion_pinAuth:
                result = parser_get_assertion_pin_auth(&map, &get_assertion->pin_auth_);
                if (result == FIDO_ERR_SUCCESS)
                    get_assertion->params_ |= GetAssertionParam_pinAuth;
                break;
            case GetAssertion_pinProtocol:
                result = parser_get_assertion_pin_protocol(&map, &get_assertion->pin_protocol_);
                if (result == FIDO_ERR_SUCCESS)
                    get_assertion->params_ |= GetAssertionParam_pinProtocol;
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

    if (result == FIDO_ERR_SUCCESS)
        cbor_value_leave_container(&iter, &map);

    return result;
}

uint8_t ctap2_parser_client_pin(uint8_t *dat, uint16_t len, ClientPin *client_pin)
{
    CborParser  parser;
    CborValue   iter, map;

    if (cbor_parser_init(dat, len, CborValidateCanonicalFormat, &parser, &iter) != CborNoError)
        return FIDO_ERR_INVALID_CBOR;
    if (cbor_value_get_type(&iter) != CborMapType)
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

        for (uint32_t i = 0; i < map_size; i++)
        {
            int     key;

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
            case ClientPIN_pinProtocol:
                result = parser_client_pin_pin_protocol(&map, &client_pin->pin_protocol_);
                if (result == FIDO_ERR_SUCCESS)
                    client_pin->params_ |= ClientPinParam_pinProtocol;
                break;
            case ClientPIN_subCommand:
                result = parser_client_pin_sub_command(&map, &client_pin->sub_command_);
                if (result == FIDO_ERR_SUCCESS)
                    client_pin->params_ |= ClientPinParam_subCommand;
                break;
            case ClientPIN_keyAgreement:
                result = parser_client_pin_key_agreement(&map, &client_pin->key_agreement_);
                if (result == FIDO_ERR_SUCCESS)
                    client_pin->params_ |= ClientPinParam_keyAgreement;
                break;
            case ClientPIN_pinAuth:
                result = parser_client_pin_pin_auth(&map, &client_pin->pin_auth_);
                if (result == FIDO_ERR_SUCCESS)
                    client_pin->params_ |= ClientPinParam_pinAuth;
                break;
            case ClientPIN_newPinEnc:
                result = parser_client_pin_new_pin_enc(&map, &client_pin->new_pin_enc_);
                if (result == FIDO_ERR_SUCCESS)
                    client_pin->params_ |= ClientPinParam_newPinEnc;
                break;
            case ClientPIN_pinHashEnc:
                result = parser_client_pin_pin_hash_enc(&map, &client_pin->pin_hash_enc_);
                if (result == FIDO_ERR_SUCCESS)
                    client_pin->params_ |= ClientPinParam_pinHashEnc;
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

    if (result == FIDO_ERR_SUCCESS)
        cbor_value_leave_container(&iter, &map);

    return result;
}

/* end of file ****************************************************************************************************** */
