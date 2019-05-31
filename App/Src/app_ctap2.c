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
#include "ctap2_maker.h"
#include "cnm_worker.h"
#include "cnm_buffer.h"
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
        // getAssertion
        _GetAssertion_UserPresence_up,
        _GetAssertion_UserPresence_uv,
        _GetAssertion_getNextAssertion,
        _GetAssertion_run,
        // getNextAssertion
        _GetNextAssertion_run,
        // authenticatorReset
        _AuthenticatorReset_run,
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

    CredentialList      credentials_;

    int8_t     credential_count_;
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

static bool authenticate_credential(RelyingPartyId *rp_id, CredentialDescriptor *cred_desc)
{
    if (cred_desc->type_ == CREDENTIAL_TYPE_publicKey)
    {
        uint8_t     tag[CTAP2_MESSAGE_DIGEST_SIZE];

        make_fido_tag(rp_id->id_, sizeof(rp_id->id_), cred_desc->id_.seed_, sizeof(cred_desc->id_.seed_), tag);
        if (memcmp(cred_desc->id_.tag_, tag, sizeof(cred_desc->id_.tag_)) == 0)
            return true;
    }

    return false;
}

static void make_credential_id(RelyingPartyId *rpid, CredentialId *cred_id)
{
    uint8_t     tag[CTAP2_MESSAGE_DIGEST_SIZE];

    device_get_rng(cred_id->nonce_, sizeof(cred_id->nonce_));
    cred_id->count_ = device_get_info()->counter_++;
    make_fido_tag(rpid->id_, sizeof(rpid->id_), cred_id->seed_, sizeof(cred_id->seed_), tag);
    memcpy(cred_id->tag_, tag, sizeof(cred_id->tag_));
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
    uint8_t     pin_command[5] = { PIN_CLASS, PIN_INS_TOUCH, 0, 0, 0 };

    if ((status == _GetAssertion_UserPresence_uv) || (status == _AuthenticatorReset_run))
        pin_command[2] = PIN_INS_CHECK;

    pin_postman(this->cid_, pin_command, 5, now_ms);
    this->status_       = status;
    this->keepalive_ms_ = now_ms + CTAP2_KEEPALIVE_INTERVAL_MS;
    this->timeout_ms_   = now_ms + CTAP2_TIMEOUT_MS;
}

static bool load_credential(RelyingPartyId *rpid, CredentialDescriptor *cred_desc, Credential *credential)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    DataBlob    blob;
    uint8_t     rpid_hash[sizeof(blob.blob_.rpid_hash_)];

    mbedtls_md(md_info, rpid->id_, sizeof(rpid->id_), rpid_hash);

    for (int16_t index = 0; device_load_blob(index, &blob); index++)
    {
        if ((memcmp(blob.blob_.rpid_hash_, rpid_hash, sizeof(rpid_hash)) == 0) &&
                (memcmp(blob.blob_.cred_id_, cred_desc->id_.bytes_, sizeof(blob.blob_.cred_id_)) == 0))
        {
            credential->desc_ = *cred_desc;
            memcpy(credential->user_.id_, blob.blob_.user_id_, sizeof(credential->user_.id_));
            memcpy(credential->user_.disp_name_, blob.blob_.disp_name_, sizeof(credential->user_.disp_name_));

            return true;
        }
    }

    return false;
}

static void load_credential_with_rpid(RelyingPartyId *rpid, CredentialList *cred_list)
{
    CredentialDescriptor    *desc = &cred_list->credentials_[cred_list->count_].desc_;
    CredentialUserEntity    *user = &cred_list->credentials_[cred_list->count_].user_;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    DataBlob    blob;
    uint8_t     rpid_hash[mbedtls_md_get_size(md_info)];
    int8_t      max_count = sizeof(cred_list->credentials_) / sizeof(cred_list->credentials_[0]);

    mbedtls_md(md_info, rpid->id_, sizeof(rpid->id_), rpid_hash);

    for (int16_t index = 0; device_load_blob(index, &blob); index++)
    {
        if (memcmp(rpid_hash, blob.blob_.rpid_hash_, sizeof(rpid_hash)) == 0)
        {
            desc->type_ = CREDENTIAL_TYPE_publicKey;
            memcpy(desc->id_.bytes_, blob.blob_.cred_id_, sizeof(desc->id_));
            memcpy(user->id_, blob.blob_.user_id_, sizeof(user->id_));
            memcpy(user->disp_name_, blob.blob_.disp_name_, sizeof(user->disp_name_));
            cred_list->count_++;

            if (cred_list->count_ >= max_count)
                break;
        }
    }
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

        /**
         * step 1. excludeList
         */

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

        /**
         * step 2. pubKeyCredParams
         */

        if (mc->params_ | MakeCredential_pubKeyCredParams)
        {
            result = FIDO_ERR_UNSUPPORTED_ALGORITHM;

            for (int8_t i = 0; i < mc->cred_param_list_.count_; i++)
            {
                if (check_cose_algorithm(mc->cred_param_list_.params_[i].alg_))
                {
                    result = FIDO_ERR_SUCCESS;
                    break;
                }
            }

            if (result != FIDO_ERR_SUCCESS)
                break;
        }

        /**
         * step 3. oiptions
         */

        if (mc->params_ | MakeCredentialParam_options)
        {
            if (mc->options_.up_)
            {
                result = FIDO_ERR_INVALID_OPTION;
                break;
            }
        }

        /**
         * step 4. extensions
         *  : not here
         */

        /**
         * step 5. pinAuth
         * step 6. pinAuth & clientPin
         * step 7. pinAuth & pinProtocol
         */

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
            else
            {
                result = FIDO_ERR_PIN_AUTH_INVALID;
                break;
            }
        }
        else
        {
            if (device_get_auth()->client_pin_)
            {
                result = FIDO_ERR_PIN_REQUIRED;
                break;
            }
        }

        /**
         * step 8. user interaction
         */

        request_user_presence(this, _MakeCredential_UserPresence_createCredential, now_ms);
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
    {
        hidif_error(this->cid_, result);
        process_term(this);
    }
}

static void lease_make_credential(Ctap2Data *this)
{
    MakeCredential  *mc = &this->make_credential_;
    uint8_t         result = FIDO_ERR_SUCCESS;

    do
    {
        CredentialId    *credential_id = &this->credentials_.credentials_[0].desc_.id_;
        RelyingPartyId  *rpid = &mc->relying_party_.id_;
        UserEntity      *user = &mc->user_;

        /**
         * step 9. generate a new credential key pair
         */

        make_credential_id(rpid, credential_id);

        /**
         * step 10. rk
         */

        if ((mc->params_ | MakeCredentialParam_options) && mc->options_.rk_)
        {
            const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            DataBlob        blob;

            memset(&blob, 0, sizeof(blob));

            // rpId's SHA256 - reduce the flash area
            mbedtls_md(md_info, rpid->id_, sizeof(rpid->id_), blob.blob_.rpid_hash_);
            // credentialId
            memcpy(blob.blob_.cred_id_, credential_id->bytes_, sizeof(*credential_id));
            // userId
            memcpy(blob.blob_.user_id_, user->id_, sizeof(user->id_));
            // displayName
            memcpy(blob.blob_.disp_name_, user->disp_name_, sizeof(user->disp_name_));

            if (device_save_blob(&blob) == false)
            {
                result = FIDO_ERR_CREDENTIAL_EXCLUDED;
                break;
            }
        }

        /**
         * step 11. generate an attestation statement
         */

        ba_hidif.add_byte(FIDO_ERR_SUCCESS);

        uint16_t    buffer_size = ba_hidif.remain();

        result = ctap2_maker_make_credential(mc, credential_id, ba_hidif.get(), &buffer_size);
        if (result != FIDO_ERR_SUCCESS)
            break;
        ba_hidif.set(true, buffer_size);
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
        hidif_error(this->cid_, result);

    process_term(this);
}

static void try_get_assertion(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    memset(&this->get_assertion_, 0, sizeof(this->get_assertion_));

    GetAssertion    *ga = &this->get_assertion_;
    uint8_t         result = ctap2_parser_get_assertion(dat, len, ga);

    do
    {
        if (result != FIDO_ERR_SUCCESS)
            break;

        if ((ga->params_ | GetAssertionParam_Required) != GetAssertionParam_Required)
        {
            result = FIDO_ERR_INVALID_PARAMETER;
            break;
        }

        CredentialList  *credential_list = &this->credentials_;

        memset(credential_list, 0, sizeof(*credential_list));

        /**
         * step 1. allowList
         * step 8. no credentials
         * step 9. applicable credentials
         */

        if (ga->params_ | GetAssertionParam_allowList)
        {
            int8_t  max_credentials = sizeof(credential_list->credentials_) / sizeof(credential_list->credentials_[0]);

            for (int8_t i = 0; i < ga->allow_list_.count_;  i++)
            {
                if (authenticate_credential(&ga->rp_id_, &ga->allow_list_.descs_[i]) &&
                        load_credential(&ga->rp_id_, &ga->allow_list_.descs_[i],
                                &credential_list->credentials_[credential_list->count_]))
                {
                    credential_list->count_++;
                    if (credential_list->count_ >= max_credentials)
                        break;
                }
            }
        }
        else
        {
            load_credential_with_rpid(&ga->rp_id_, credential_list);
        }

        if (credential_list->count_ == 0)
        {
            result = FIDO_ERR_NO_CREDENTIALS;
            break;
        }

        /**
         * step 2. pinAuth
         * step 3. pinAuth & pinProtocol
         * step 4. pinAuth & clientPin
         */

        if (ga->params_ | GetAssertionParam_pinAuth)
        {
            if ((ga->params_ | GetAssertionParam_pinProtocol) && check_pin_protocol(ga->pin_protocol_.version_))
            {
                const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
                uint8_t hash[mbedtls_md_get_size(md_info)];

                mbedtls_md_hmac(md_info, device_get_auth()->pin_token_, sizeof(device_get_auth()->pin_token_),
                        ga->client_data_hash_.hash_, sizeof(ga->client_data_hash_.hash_), hash);
                if (memcmp(hash, ga->pin_auth_.auth_, sizeof(ga->pin_auth_.auth_)) == 0)
                {
                    device_get_auth()->uv_ = true;
                }
                else
                {
                    result = FIDO_ERR_PIN_AUTH_INVALID;
                    break;
                }
            }
            else
            {
                result = FIDO_ERR_PIN_AUTH_INVALID;
                break;
            }
        }
        else
        {
            if (device_get_auth()->client_pin_)
                device_get_auth()->uv_ = false;
        }

        /**
         * step 6. extensions
         *  : not here
         */

        /**
         * step 5. options
         * step 7. user consent
         */

        if (ga->params_ | GetAssertionParam_options)
        {
            if (ga->options_.rk_)
            {
                result = FIDO_ERR_INVALID_OPTION;
                break;
            }

            if (ga->options_.up_)
            {
                request_user_presence(this, _GetAssertion_UserPresence_up, now_ms);
                break;
            }

            if (ga->options_.uv_)
            {
                request_user_presence(this, _GetAssertion_UserPresence_uv, now_ms);
                break;
            }
        }

        this->status_ = _GetAssertion_run;
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
    {
        hidif_error(this->cid_, result);
        process_term(this);
    }
}

static void lease_get_assertion(Ctap2Data *this)
{
    GetAssertion    *ga = &this->get_assertion_;
    CredentialList  *credential_list = &this->credentials_;
    uint8_t         result;

    do
    {
        /**
         * step 10. does not have display
         * step 12. sign the clientDataHash
         */

        ba_hidif.add_byte(FIDO_ERR_SUCCESS);

        uint16_t    buffer_size = ba_hidif.remain();

        this->credential_count_ = 1;
        result = ctap2_maker_get_assertion(ga, credential_list, this->credential_count_, ba_hidif.get(), &buffer_size);
        if (result != FIDO_ERR_SUCCESS)
            break;
        ba_hidif.set(true, buffer_size);

        this->status_ = _GetAssertion_getNextAssertion;
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
    {
        hidif_error(this->cid_, result);
        process_term(this);
    }
}

static void try_get_info(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    ba_hidif.add_byte(FIDO_ERR_SUCCESS);

    uint16_t    buffer_size = ba_hidif.remain();
    uint8_t     result = ctap2_maker_get_info(ba_hidif.get(), &buffer_size);

    ba_hidif.set(true, buffer_size);

    if (result != FIDO_ERR_SUCCESS)
        hidif_error(this->cid_, result);
    process_term(this);
}

static void try_client_pin(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    memset(&this->client_pin_, 0, sizeof(this->client_pin_));

    ClientPin   *cp = &this->client_pin_;
    uint8_t     result = ctap2_parser_client_pin(dat, len, cp);

    do
    {
        if (result != FIDO_ERR_SUCCESS)
            break;

        if ((cp->params_ | ClientPinParam_Required) != ClientPinParam_Required)
        {
            result = FIDO_ERR_INVALID_PARAMETER;
            break;
        }

        if ((cp->params_ | ClientPinParam_pinProtocol) && (cp->pin_protocol_.version_ != FIDO2_PIN_PROTOCOL_VER))
        {
            result = FIDO_ERR_INVALID_PARAMETER;
            break;
        }

        ba_hidif.add_byte(FIDO_ERR_SUCCESS);

        uint16_t    buffer_size = ba_hidif.remain();

        result = ctap2_maker_client_pin(cp, ba_hidif.get(), &buffer_size);
        if (result != FIDO_ERR_SUCCESS)
            break;
        ba_hidif.set(true, buffer_size);
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
    {
        hidif_error(this->cid_, result);
        process_term(this);
    }
}

static void try_reset(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    request_user_presence(this, _AuthenticatorReset_run, now_ms);
}

static void lease_reset(Ctap2Data *this)
{
    device_reset();

    ba_hidif.flush();
    ba_hidif.add_byte(FIDO_ERR_SUCCESS);
    process_term(this);
}

static void try_get_next_assertion(Ctap2Data *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    GetAssertion    *ga = &this->get_assertion_;
    CredentialList  *credential_list = &this->credentials_;
    uint8_t         result;

    do
    {
        /**
         * step 1. empty authenticator
         */

        if ((this->status_ != _GetAssertion_getNextAssertion) || (this->status_ != _GetNextAssertion_run))
        {
            result = FIDO_ERR_NOT_ALLOWED;
            break;
        }

        /**
         * step 2. credentialCounter
         */

        if (this->credentials_.count_ == this->credential_count_)
        {
            result = FIDO_ERR_NOT_ALLOWED;
            break;
        }

        /**
         * step 3. timer
         *  : not here
         */

        /**
         * step 4. sign
         * step 5. timer
         * step 6. credentialCounter
         */

        ba_hidif.add_byte(FIDO_ERR_SUCCESS);

        uint16_t    buffer_size = ba_hidif.remain();

        this->credential_count_++;
        result = ctap2_maker_get_assertion(ga, credential_list, this->credential_count_, ba_hidif.get(), &buffer_size);
        if (result != FIDO_ERR_SUCCESS)
            break;
        ba_hidif.set(true, buffer_size);

        this->status_ = _GetNextAssertion_run;
    }
    while (0);

    if (result != FIDO_ERR_SUCCESS)
    {
        hidif_error(this->cid_, result);
        process_term(this);
    }
}

static bool wakeup_func(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    Ctap2Data   *this = (Ctap2Data*)param;
    bool        wakeup = false;

    switch (this->status_)
    {
    case _MakeCredential_UserPresence_excludeList:
    case _MakeCredential_UserPresence_createCredential:
    case _GetAssertion_UserPresence_up:
    case _GetAssertion_UserPresence_uv:
    case _GetAssertion_getNextAssertion:
    case _GetAssertion_run:
    case _GetNextAssertion_run:
    case _AuthenticatorReset_run:

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

                this->keepalive_ms_ = now_ms + CTAP2_KEEPALIVE_INTERVAL_MS;
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
    case _GetAssertion_UserPresence_up:
    case _GetAssertion_UserPresence_uv:
    case _GetAssertion_getNextAssertion:
    case _GetAssertion_run:
        lease_get_assertion(this);
        break;
    case _GetNextAssertion_run:
        break;
    case _AuthenticatorReset_run:
        lease_reset(this);
        break;
    default:
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
        try_reset(&_ctap2_data, dat + 1, len - 1, now_ms);
        break;
    case authenticatorGetNextAssertion:
        try_get_next_assertion(&_ctap2_data, dat + 1, len - 1, now_ms);
        break;
    default:
        hidif_append_sw(FIDO_SW_CLA_NOT_SUPPORTED);
        process_term(&_ctap2_data);
        break;
    }
}

/* end of file ****************************************************************************************************** */
