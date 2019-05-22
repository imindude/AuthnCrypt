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
#include "mbedtls/md.h"

/* ****************************************************************************************************************** */

#define CTAP2_KEEPALIVE_INTERVAL_MS     100
#define CTAP2_TIMEOUT_MS                20000

#define CTAP2_MESSAGE_DIGEST_SIZE       32

struct Ctap2Data
{
    enum
    {
        _Idle_,
        // makeCredential
        _MakeCredential_UserPresence_excludeList,
        _MakeCredential_UserPresence_createCredential,
        _MakeCredential_AfterExcludeList,
        _MakeCredential_AfterCreateCredential,
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
    hidif_write(this->cid_, HIDIF_CBOR);
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
        uint8_t     tag[CTAP2_MESSAGE_DIGEST_SIZE];

        make_fido_tag((uint8_t*)rp_id->id_, sizeof(rp_id->id_), desc->id_.seed_, sizeof(desc->id_.seed_), tag);
        if (memcmp(desc->id_.tag_, tag, sizeof(desc->id_.tag_)) == 0)
            return true;
    }

    return false;
}

static void make_credential_id(RelyingPartyId *rpid, CredentialId *credential_id)
{
    uint8_t     tag[CTAP2_MESSAGE_DIGEST_SIZE];

    device_get_rng(credential_id->nonce_, sizeof(credential_id->nonce_));
    credential_id->count_ = device_get_counter();
    make_fido_tag((uint8_t*)rpid->id_, sizeof(rpid->id_), credential_id->seed_, sizeof(credential_id->seed_), tag);
    memcpy(credential_id->tag_, tag, sizeof(credential_id->tag_));
}

static bool check_cose_algorithm(int32_t alg)
{
    return (alg == COSE_Alg_ES256) ? true : false;
}

static bool check_pin_protocol(uint32_t ver)
{
    return (ver == FIDO2_PIN_PROTOCOL_VER) ? true : false;
}

static void request_user_presence(Ctap2Data *this, uint8_t status, uint32_t now_ms)
{
    uint8_t     pin_command[5] = { PIN_CLASS, PIN_INS_CHECK, 0, 0, 0 };

    pin_postman(this->cid_, pin_command, 5, now_ms);
    this->status_       = status;
    this->keepalive_ms_ = now_ms + CTAP2_KEEPALIVE_INTERVAL_MS;
    this->timeout_ms_   = now_ms + CTAP2_TIMEOUT_MS;
}

static void try_make_credential(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    memset(&this->make_credential_, 0, sizeof(this->make_credential_));

    MakeCredential  *mc = &this->make_credential_;
    uint8_t         result = ctap2_parser_make_credential(dat, len, mc);

    do
    {
        if (result != FIDO_ERR_SUCCESS)
            break;

        if ((mc->params_ | MakeCredentialParam_Required) != MakeCredentialParam_Required)
        {
            result = FIDO_ERR_INVALID_PARAMETER;
            break;
        }

        /* step 1. excludeList */

        if (mc->params_ | MakeCredentialParam_excludeList)
        {
            for (int8_t i = 0; i < mc->exclude_list_.count_; i++)
            {
                if (authenticate_credential(&mc->relying_party_.id_, &mc->exclude_list_.descs_[i]))
                {
                    request_user_presence(this, _MakeCredential_UserPresence_excludeList, now_ms);
                    break;
                }
            }
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
                // require resident key
                // https://www.w3.org/TR/webauthn/#dom-authenticatorselectioncriteria-requireresidentkey
            }

            if (mc->options_.uv_)
            {
                // always true
                // pass
            }
        }

        /* step 4. extensions */

        if (mc->params_ | MakeCredentialParam_extensions)
        {
            if (mc->extensions_.type_ == _HmacSecret_Create)
            {
                // good
                // don't care
            }
        }

        /* step 5. pinAuth */

        if (mc->params_ | MakeCredentialParam_pinAuth)
        {
            if ((mc->params_ | MakeCredentialParam_pinProtocol) && check_pin_protocol(mc->pin_protocol_.version_))
            {
                const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
                uint8_t hash[mbedtls_md_get_size(md_info)];

                mbedtls_md_hmac(md_info, device_get_auth()->pin_token_, sizeof(device_get_auth()->pin_token_),
                        mc->client_data_hash_.hash_, sizeof(mc->client_data_hash_.hash_), hash);

                if (memcmp(hash, mc->pin_auth_.auth_, sizeof(mc->pin_auth_.auth_)) == 0)
                {
                    device_get_auth()->uv_ = true;
                }
                else
                {
                    result = FIDO_ERR_PIN_AUTH_INVALID;
                    break;
                }
            }
        }

        /* step 6. pinAuth & clientPin */

        if (device_get_auth()->client_pin_)
        {
            if ((mc->params_ | MakeCredentialParam_pinAuth) != MakeCredentialParam_pinAuth)
            {
                result = FIDO_ERR_PIN_REQUIRED;
                break;
            }
        }

        /* step 7. pinAuth & pinProtocol */

        if ((mc->params_ | MakeCredentialParam_pinAuth) && (check_pin_protocol(mc->pin_protocol_.version_) == false))
        {
            result = FIDO_ERR_PIN_AUTH_INVALID;
            break;
        }

        /* step 8. user interaction */

        request_user_presence(this, _MakeCredential_UserPresence_createCredential, now_ms);
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
    {
        hidif_error(result);
        process_term(this);
    }
}

static void lease_make_credential(Ctap2Data *this)
{
    MakeCredential  *mc = &this->make_credential_;
    uint8_t     result = FIDO_ERR_SUCCESS;

    do
    {
        CredentialId    credential_id;
        RelyingPartyId  *rpid = &mc->relying_party_.id_;
        UserEntity      *user = &mc->user_;

        /* step 9. generate a new credential key pair */

        make_credential_id(rpid, &credential_id);

        /* step 10. rk */

        if ((mc->params_ | MakeCredentialParam_options) && mc->options_.rk_)
        {
            DataBlob        blob;
            BufferHandle    bh =
            {
                    .buffer_    = blob.blob_.data_,
                    .max_size_  = sizeof(blob.bytes_) - sizeof(blob.blob_.usage_),
                    .used_size_ = 0
            };

            memset(&blob, 0, sizeof(blob));

            // rpId
            buif_add_bytes_unsafe(&bh, rpid->id_, sizeof(rpid->id_));
            // userId
            buif_add_bytes_unsafe(&bh, user->id_, sizeof(user->id_));
            // credentialId
            buif_add_bytes_unsafe(&bh, credential_id.bytes_, sizeof(credential_id));

            if (device_save_blob(&blob) == false)
            {
                result = FIDO_ERR_CREDENTIAL_EXCLUDED;
                break;
            }
        }

        /* step 11. generate an attestation statement */

        result = ctap2_maker_make_credential(mc, &credential_id);
        if (result != FIDO_ERR_SUCCESS)
            break;

        // DONE!!
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
        hidif_error(result);

    process_term(this);
}

static void try_get_assertion(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    memset(&this->get_assertion_, 0, sizeof(this->get_assertion_));
}

static void try_get_info(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
}

static void try_client_pin(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    memset(&this->client_pin_, 0, sizeof(this->client_pin_));
}

static bool wakeup_func(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    Ctap2Data   *this = (Ctap2Data*)param;
    bool        wakeup = false;

    switch (this->status_)
    {
    case _MakeCredential_UserPresence_excludeList:
    case _MakeCredential_UserPresence_createCredential:

        if (!process_timeout(this, now_ms))
        {
            if (device_get_info()->pin_confirmed_)
            {
                wakeup = true;
            }
            else if (now_ms > this->keepalive_ms_)
            {
                hidif_add_byte(KEEPALIVE_TUP_NEEDED);
                hidif_write(this->cid_, HIDIF_KEEPALIVE);

                this->keepalive_ms_ = now_ms + CTAP1_KEEPALIVE_INTERVAL_MS;
            }
        }

        break;

    default:

        // do nothing
        break;
    }

    return wakeup;
}

static void worker_func(uint32_t now_ms, uint32_t worker_ms, void *param)
{
    Ctap2Data   *this = (Ctap2Data*)param;

    switch (this->status_)
    {
    case _MakeCredential_UserPresence_excludeList:
        hidif_error(this->cid_, FIDO_ERR_CREDENTIAL_EXCLUDED);
        process_term(this);
        break;
    case _MakeCredential_UserPresence_createCredential:
        lease_make_credential(this);
        break;
    }
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
