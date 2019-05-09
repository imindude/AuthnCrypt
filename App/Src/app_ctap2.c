/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "app_ctap2.h"
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
        MakeCredential  make_credential_;
        GetAssertion    get_assertion_;
        ClientPin       client_pin_;
    };
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

static bool authenticate_credential(RelyingPartyId *rp_id, PubKeyCredDesc *desc)
{
    if (desc->type_ == CREDENTIAL_TYPE_publicKey)
    {
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        uint8_t     hash[mbedtls_md_get_size(md_info)];
        uint8_t     tag[32];

        mbedtls_md_hmac(md_info, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_),
                rp_id->id_, sizeof(rp_id->id_), hash);
        make_fido_tag(hash, sizeof(hash), desc->id_.nonce_, sizeof(desc->id_.nonce_), tag);

        if (memcmp(desc->id_.tag_, tag, sizeof(desc->id_.tag_)) == 0)
            return true;
    }

    return false;
}

static bool check_cose_algorithm(int32_t alg)
{
    return (alg == COSE_Alg_ES256) ? true : false;
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
    memset(&this->make_credential_, 0, sizeof(this->make_credential_));

    uint8_t     result = ctap2_parser_make_credential(dat, len, &this->make_credential_);

    if (result == FIDO_ERR_SUCCESS)
    {
        if ((this->make_credential_.params_ | MakeCredentialParam_Required) == MakeCredentialParam_Required)
        {
            this->status_ = _MakeCredential_UserPresent_;
            // good to work
            return ;
        }
        else
        {
            result = FIDO_ERR_INVALID_PARAMETER;
        }
    }

    // error something
    // result
}

static void lease_make_credential(Ctap2Data *this)
{
    MakeCredential  *mc = &this->make_credential_;
    uint8_t     result = FIDO_ERR_SUCCESS;

    do
    {
        /* step 1. excludeList */

        if (mc->params_ | MakeCredentialParam_excludeList)
        {
            for (int8_t i = 0; i < mc->exclude_list_.count_; i++)
            {
                if (authenticate_credential(&mc->relying_party_.id_, &mc->exclude_list_.descs_[i]))
                {
                    result = FIDO_ERR_CREDENTIAL_EXCLUDED;
                    break;
                }
            }

            if (result != FIDO_ERR_SUCCESS)
                break;
        }

        /* step 2. pubKeyCredParams */

        if (mc->params_ | MakeCredential_pubKeyCredParams)
        {
            result = FIDO_ERR_UNSUPPORTED_ALGORITHM;

            for (int8_t i = 0; i < mc->pubkey_cred_param_.count_; i++)
            {
                if (check_cose_algorithm(mc->pubkey_cred_param_.params_[i].alg_))
                {
                    result = FIDO_ERR_SUCCESS;
                    break;
                }
            }

            if (result != FIDO_ERR_SUCCESS)
                break;
        }

        /* step 3. oiptions */

        if (mc->params_ | MakeCredentialParam_options)
        {
            if (mc->options_.up_)
            {
                result = FIDO_ERR_INVALID_OPTION;
                break;
            }

            if (mc->options_.rk_)
            {
                // store resident key
            }

            if (mc->options_.uv_)
            {
                // always true
                // ????
            }
        }
    }
    while (0);

    // do something
}

static void try_get_assertion(Ctap2Data *this, uint8_t *dat, uint16_t len)
{
    memset(&this->get_assertion_, 0, sizeof(this->get_assertion_));
    memset(&this->credential_list_, 0, sizeof(this->credential_list_));
}

static void try_get_info(Ctap2Data *this, uint8_t *dat, uint16_t len)
{
    memset(&this->get_info_, 0, sizeof(this->get_info_));
}

static void try_client_pin(Ctap2Data *this, uint8_t *dat, uint16_t len)
{
    memset(&this->client_pin_, 0, sizeof(this->client_pin_));
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
        try_get_assertion(&_ctap2_data, dat + 1, len - 1, now_ms);
        break;
    case authenticatorGetInfo:
        try_get_info(&_ctap2_data, dat + 1, len - 1, now_ms);
        break;
    case authenticatorClientPIN:
        try_client_pin(&_ctap2_data, dat + 1, len - 1, now_ms);
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
