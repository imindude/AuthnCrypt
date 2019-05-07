/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "app_ctap2.h"
#include "fidodef.h"
#include "app_def.h"
#include "app_device.h"
#include "app_hidif.h"
#include "app_status.h"
#include "app_pin.h"
#include "app_misc.h"
#include "ctap2_parser.h"
#include "cnm_worker.h"
#include "hwl_rng.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"

/* ****************************************************************************************************************** */

#define CTAP2_KEEPALIVE_INTERVAL_MS     100
#define CTAP2_TIMEOUT_MS                20000

#define CTAP2_RPID_HASH_SIZE            32
#define CTAP2_NONCE_SIZE                32
#define CTAP2_CREDENTIAL_TAG_SIZE       32

struct PinToken
{
    uint8_t token_[16];
};
typedef struct PinToken     PinToken;

struct Ctap2Data
{
    enum
    {
        _Idle_,
        _MakeCredential_UserPresent_,
    }
    status_;

    uint32_t    cid_;
    uint32_t    keepalive_ms_;
    uint32_t    timeout_ms_;

    union
    {
        MakeCredential  make_cred_;
    };
    PinToken            pin_token_;
};
typedef struct Ctap2Data    Ctap2Data;

/* ****************************************************************************************************************** */

static Ctap2Data    _ctap2_data;

/* ****************************************************************************************************************** */

static void process_term(Ctap2Data *this)
{
    hidif_write(this->cid_, HIDIF_MSG);
    memset(this, 0, sizeof(Ctap2Data));
    status_reset();
    pin_reset();
}

static bool process_timeout(Ctap2Data *this, uint32_t now_ms)
{
    if (now_ms > this->timeout_ms_)
    {
        hidif_error(this->cid_, FIDO_ERR_TIMEOUT);
        process_term(this);

        return true;
    }

    return false;
}

static uint8_t verify_pin_auth(PinToken *pin_token, PinAuthEntity *pin_auth, ClientDataHashEntity *client_data_hash)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;
    uint8_t     md_hash[mbedtls_md_get_size(md_info)];

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    mbedtls_md_hmac_starts(&md_ctx, pin_token->token_, sizeof(pin_token->token_));
    mbedtls_md_hmac_update(&md_ctx, client_data_hash->hash_, sizeof(client_data_hash->hash_));
    mbedtls_md_hmac_finish(&md_ctx, md_hash);
    mbedtls_md_free(&md_ctx);

    return (memcmp(pin_auth->pin_, md_hash, sizeof(pin_auth->pin_)) == 0) ?
            FIDO_ERR_SUCCESS : FIDO_ERR_PIN_AUTH_INVALID;
}

static bool authenticate_credential(RelyingPartyEntity *rp, CredentialDesc *desc)
{
    CredentialId    *cred_id = &desc->credential_.id_;

    if (desc->type_ == CREDENTIAL_TYPE_Public_Key)
    {
        uint8_t     tag[CTAP2_CREDENTIAL_TAG_SIZE];

        make_ctap2_tag(cred_id->rpid_hash_, sizeof(cred_id->rpid_hash_), cred_id->nonce_, sizeof(cred_id->nonce_),
                cred_id->count_, tag);
        if (memcmp(cred_id->tag_, tag, CTAP2_CREDENTIAL_TAG_SIZE) == 0)
            return true;
    }
    else if (desc->type_ == CREDENTIAL_TYPE_CTAP1)
    {
        uint8_t     appl_param[CTAP1_APPL_PARAM_SIZE];
        uint8_t     tag[CTAP1_TAG_SIZE];

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), rp->id_, sizeof(rp->id_), appl_param);
        make_ctap1_tag(appl_param, sizeof(appl_param), (uint8_t*)cred_id, CTAP1_KEY_SIZE, tag);
        if (memcmp(cred_id->tag_, tag, CTAP2_CREDENTIAL_TAG_SIZE) == 0)
            return true;
    }

    return false;
}

static uint8_t make_extensions(ExtensionsEntity *extensions, uint8_t *buffer, size_t *size)
{
    uint8_t         result = FIDO_ERR_SUCCESS;
    CborEncoder     encoder;
    CborEncoder     map;

    if (extensions->hmac_request_ == _HmacSecretCreate)
    {
        cbor_encoder_init(&encoder, buffer, *size, 0);

        cbor_encoder_create_map(&encoder, &map, 1);
        cbor_encode_text_stringz(&map, "hmac-secret");
        cbor_encode_boolean(&map, true);
        cbor_encoder_close_container(&encoder, &map);

        *size = cbor_encoder_get_buffer_size(&encoder, buffer);
    }
    else if (extensions->hmac_request_ == _HmacSecretGet)
    {
        CoseKey     *cose = &extensions->hmac_secret_.cose_key_;
        uint8_t     pub_key[65];
        int16_t     pub_len = sizeof(pub_key);

        make_ecdsa_shared_secret(cose->d_, sizeof(cose->d_), pub_key, &pub_len);
        memcpy(cose->x_, pub_key + 1, 32);
        memcpy(cose->y_, pub_key + 1 + 32, 32);
        cose->crv_ = 0;// ????

    }
    else
    {
        *size = 0;
    }

    return result;
}

static void try_make_credential(Ctap2Data *this, uint8_t *dat, uint16_t len)
{
    memset(&this->make_cred_, 0, sizeof(MakeCredential));
    memset(&this->cred_list_, 0, sizeof(CborCredentialList));

    MakeCredential      *make_cred = &this->make_cred_;
    uint8_t     result = ctap2_parser_make_credential(dat, len, make_cred);

    if (result != FIDO_ERR_SUCCESS)
    {
        // error
        // result
        return;
    }

    /* procedure 1. excludeList */

    if (cred_list->count_ > 0)
    {
        CredentialDesc      cred_desc;

        for (uint32_t i = 0; i < cred_list->count_; i++)
        {
            result = ctap2_parser_credential_descriptor(&cred_list->value_, &cred_desc);
            if (result != FIDO_ERR_SUCCESS)
            {
                // error
                // result;
                return;
            }
            if (authenticate_credential(&make_cred->relying_party_, &cred_desc) == false)
            {
                // error
                // FIDO_ERR_CREDENTIAL_EXCLUDED;
                return;
            }

            if (cbor_value_advance(&cred_list->value_) != CborNoError)
            {
                // error
                // FIDO_ERR_INVALID_CBOR;
                return;
            }
        }
    }

    /* procedure 2. pubKeyCredparams */

    if ((make_cred->pubkey_cred_param_.type_ != CREDENTIAL_TYPE_Public_Key) ||
            (make_cred->pubkey_cred_param_.type_ != CREDENTIAL_TYPE_CTAP1))
    {
        // error
        // FIDO_ERR_UNSUPPORTED_ALGORITHM;
        return;
    }

    /* procedure 3. options */

    if (make_cred->params_ | MakeCredentialParam_options)
    {
        OptionsEntity   *options = &make_cred->options_;

        if (options->rk_)
        {
            // resident key
            // store key material on the device
        }

        if (options->up_)
        {
            // user presence
            // maybe not
        }

        if (options->uv_)
        {
            // user verification
        }
    }

    /* procedure 4. extensions */

    if (make_cred->params_ | MakeCredentialParam_extensions)
    {
        ExtensionsEntity    *extensions = &make_cred->extensions_;
    }



    if ((make_cred->params_ | MakeCredentialParam_Required) != MakeCredentialParam_Required)
    {
        // error
        // FIDO_ERR_MISSING_PARAMETER;
        break;
    }
    if (device_need_pin())
    {
        if (make_cred->pin_auth_.presence_ == false)
        {
            // error
            // FIDO_ERR_PIN_REQUIRED;
            break;
        }
        else
        {
            result = verify_pin_auth(&this->pin_token_, &make_cred->pin_auth_, &make_cred->client_data_hash_);
            if (result != FIDO_ERR_SUCCESS)
            {
                // error
                // result;
                break;
            }
        }
    }

    if (make_cred->params_ | MakeCredentialParam_pinAuth)
    {
        uint8_t     pin_command[5] = { PIN_CLASS, PIN_INS_CHECK, 0, 0, 0 };

        pin_postman(this->cid_, pin_command, 5, now_ms);

        this->status_       = _MakeCredential_UserPresent_;
        this->keepalive_ms_ = now_ms + CTAP2_KEEPALIVE_INTERVAL_MS;
        this->timeout_ms_   = now_ms + CTAP2_TIMEOUT_MS;

        break;
    }

    lease_make_credential(this);
}

static void lease_make_credential(Ctap2Data *this)
{

}

static bool wakeup_func(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    return false;
}

static void worker_func(uint32_t now_ms, uint32_t worker_ms, void *param)
{

}

void ctap2_init(void)
{
    worker_join(wakeup_func, worker_func, _WorkerPrio_UserMid_, &_ctap2_data);
}

void ctap2_reset(void)
{
    memset(&_ctap2_data, 0, sizeof(Ctap2Data));
}

void ctap2_postman(uint32_t cid, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    _ctap2_data.cid_ = cid;

    switch (dat[0])
    {
    case authenticatorMakeCredential:
        try_make_credential(&_ctap2_data, dat + 1, len - 1, now_ms);
        break;
    case authenticatorGetAssertion:
        get_assertion(dat + 1, len - 1, now_ms);
        break;
    case authenticatorGetInfo:
        break;
    case authenticatorClientPIN:
        break;
    case authenticatorReset:
        break;
    case authenticatorGetNextAssertion:
        break;
    default:
        hidif_append_sw(FIDO_SW_CLA_NOT_SUPPORTED);
        process_term(&_ctap2_data);
        break;
    }
}

/* end of file ****************************************************************************************************** */
