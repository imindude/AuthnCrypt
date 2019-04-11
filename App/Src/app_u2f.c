/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "app_u2f.h"
#include "fidodef.h"
#include "app_def.h"
#include "app_device.h"
#include "app_hidif.h"
#include "app_status.h"
#include "app_pin.h"
#include "cnm_worker.h"
#include "hwl_rng.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"

/* ****************************************************************************************************************** */

#define U2F_KEEPALIVE_INTERVAL_MS   100
#define U2F_TIMEOUT_MS              20000

#define U2F_APPL_PARAM_SIZE     32
#define U2F_CHAL_PARAM_SIZE     32

#define U2F_KEY_SIZE            32
#define U2F_TAG_SIZE            32

#define U2F_PUBL_KEY_SIZE       65      // format(1) + X(32) + Y(32)
#define U2F_PRIV_KEY_SIZE       32
#define U2F_HASH_SIZE           32      // SHA256
#define U2F_SIGNDER_MAX_SIZE    80

#pragma pack(push, 1)

struct U2fRequest
{
    uint8_t cla_;
    uint8_t ins_;
    uint8_t p1_;
    uint8_t p2_;
    uint8_t dat_[1];
};
typedef struct U2fRequest   U2fRequest;

#pragma pack(pop)

struct U2fKey
{
    uint8_t key_[U2F_KEY_SIZE];
    uint8_t tag_[U2F_TAG_SIZE];
};
typedef struct U2fKey       U2fKey;

struct U2fData
{
    enum
    {
        _Idle_,
        _Registration_,
        _Authentication_
    }
    status_;

    uint32_t    cid_;
    uint32_t    keepalive_ms_;
    uint32_t    timeout_ms_;
    uint8_t     appl_param_[U2F_APPL_PARAM_SIZE];
    uint8_t     chal_param_[U2F_CHAL_PARAM_SIZE];
    U2fKey      key_handle_;
};
typedef struct U2fData      U2fData;

/* ****************************************************************************************************************** */

static U2fData  _u2f_data;

/* ****************************************************************************************************************** */

static void process_term(U2fData *this)
{
    hidif_write(this->cid_, HIDIF_MSG);
    memset(this, 0, sizeof(U2fData));
    status_postman(_AppStatus_Idle_);
}

static bool process_timeout(U2fData *this, uint32_t now_ms)
{
    if (now_ms > this->timeout_ms_)
    {
        hidif_error(this->cid_, FIDO_ERR_TIMEOUT);
        memset(this, 0, sizeof(U2fData));
        status_postman(_AppStatus_Idle_);

        return true;
    }

    return false;
}

static void make_u2f_tag(uint8_t *appl_param, U2fKey *hkey)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);      // HMAC ready
    mbedtls_md_hmac_starts(&md_ctx, appl_param, U2F_APPL_PARAM_SIZE);
    mbedtls_md_hmac_update(&md_ctx, device_get_info()->uid_.bytes_, DEVICE_UID_SIZE);
    mbedtls_md_hmac_update(&md_ctx, hkey->key_, U2F_KEY_SIZE);
    mbedtls_md_hmac_finish(&md_ctx, hkey->tag_);
    mbedtls_md_free(&md_ctx);
}

static void make_keypair(uint8_t *appl_param, U2fKey *hkey, uint8_t *priv_key, uint8_t *publ_key)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;
    union
    {
        uint8_t publ_key_[U2F_PUBL_KEY_SIZE];
        uint8_t priv_key_[U2F_PRIV_KEY_SIZE];
        uint8_t digest_[mbedtls_md_get_size(md_info)];
    }
    buffer;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);      // HMAC ready
    mbedtls_md_hmac_starts(&md_ctx, device_get_info()->uid_.bytes_, DEVICE_UID_SIZE);
    mbedtls_md_hmac_update(&md_ctx, hkey->key_, U2F_KEY_SIZE);
    mbedtls_md_hmac_update(&md_ctx, hkey->tag_, U2F_TAG_SIZE);
    mbedtls_md_hmac_update(&md_ctx, appl_param, U2F_APPL_PARAM_SIZE);
    mbedtls_md_finish(&md_ctx, buffer.digest_);
    mbedtls_md_free(&md_ctx);

    if (priv_key)
        memcpy(priv_key, buffer.priv_key_, U2F_PRIV_KEY_SIZE);

    if (publ_key)
    {
        mbedtls_ecdsa_context   ecdsa_ctx;
        size_t      len;

        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_ecp_group_load(&ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
        mbedtls_mpi_read_binary(&ecdsa_ctx.d, buffer.priv_key_, U2F_PRIV_KEY_SIZE);
        mbedtls_ecp_mul(&ecdsa_ctx.grp, &ecdsa_ctx.Q, &ecdsa_ctx.d, &ecdsa_ctx.grp.G, device_mbedtls_rng, NULL);
        mbedtls_ecp_point_write_binary(&ecdsa_ctx.grp, &ecdsa_ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len,
                buffer.publ_key_, U2F_PUBL_KEY_SIZE);
        mbedtls_ecdsa_free(&ecdsa_ctx);

        memcpy(publ_key, buffer.publ_key_, U2F_PUBL_KEY_SIZE);
    }
}

static bool param_parser(uint8_t *dat, uint8_t *appl_param, uint8_t *chal_param, U2fKey *hkey)
{
    uint16_t    pos, len;

    if (dat[0] > 0)
    {
        /* short encoding */

        pos = 1;
        len = dat[0];
    }
    else
    {
        /* extended length encoding (0|MSB|LSB) */

        pos = 3;
        len = dat[1] << 8 | dat[2];
    }

    if (len >= (U2F_APPL_PARAM_SIZE + U2F_CHAL_PARAM_SIZE))
    {
        memcpy(chal_param, &dat[pos], U2F_CHAL_PARAM_SIZE);
        pos += U2F_CHAL_PARAM_SIZE;
        memcpy(appl_param, &dat[pos], U2F_APPL_PARAM_SIZE);
        pos += U2F_APPL_PARAM_SIZE;

        if (hkey && (len > pos) && (dat[pos] == (U2F_APPL_PARAM_SIZE + U2F_CHAL_PARAM_SIZE)))
        {
            pos++;
            memcpy(hkey->key_, &dat[pos], U2F_KEY_SIZE);
            pos += U2F_KEY_SIZE;
            memcpy(hkey->tag_, &dat[pos], U2F_TAG_SIZE);
            pos += U2F_TAG_SIZE;
        }

        return true;
    }

    return false;
}

static void check_registration(U2fData *this, uint8_t *dat, uint16_t len)
{
    uint16_t    sw = FIDO_SW_WRONG_DATA;

    if (param_parser(dat, this->appl_param_, this->chal_param_, &this->key_handle_))
    {
        U2fKey  cmp_key;

        memcpy(cmp_key.key_, this->key_handle_.key_, U2F_KEY_SIZE);
        make_u2f_tag(this->appl_param_, &cmp_key);

        if (memcmp(cmp_key.tag_, this->key_handle_.tag_, U2F_TAG_SIZE) == 0)
            sw = FIDO_SW_CONDITINOS_NOT_SATISFIED;
    }

    hidif_append_sw(sw);
    process_term(this);
}

static void try_registration(U2fData *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    if (param_parser(dat, this->appl_param_, this->chal_param_, NULL))
    {
        uint8_t     pin_command[5] = { PIN_CLASS, PIN_INS_CHECK, 0, 0, 0 };

        pin_postman(this->cid_, pin_command, 5, now_ms);

        this->status_       = _Registration_;
        this->keepalive_ms_ = now_ms + U2F_KEEPALIVE_INTERVAL_MS;
        this->timeout_ms_   = now_ms + U2F_TIMEOUT_MS;
    }
    else
    {
        hidif_append_sw(FIDO_SW_WRONG_DATA);
        process_term(this);
    }
}

static void lease_registration(U2fData *this)
{
    uint8_t     publ_key[U2F_PUBL_KEY_SIZE];

    /* U2F key handle */

    rng_bytes(this->key_handle_.key_, U2F_KEY_SIZE);
    make_u2f_tag(this->appl_param_, &this->key_handle_);
    make_keypair(this->appl_param_, &this->key_handle_, NULL, publ_key);

    /* hash */

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;
    uint8_t     buffer[mbedtls_md_get_size(md_info)];

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);

    // reserved
    buffer[0] = 0;
    mbedtls_md_update(&md_ctx, buffer, 1);
    mbedtls_md_update(&md_ctx, this->appl_param_, U2F_APPL_PARAM_SIZE);
    mbedtls_md_update(&md_ctx, this->chal_param_, U2F_CHAL_PARAM_SIZE);
    mbedtls_md_update(&md_ctx, this->key_handle_.key_, U2F_KEY_SIZE);
    mbedtls_md_update(&md_ctx, this->key_handle_.tag_, U2F_TAG_SIZE);
    // ECC public key of uncompressed form (RFC5480 section-2.2)
    mbedtls_md_update(&md_ctx, publ_key, U2F_PUBL_KEY_SIZE);

    mbedtls_md_finish(&md_ctx, buffer);
    mbedtls_md_free(&md_ctx);

    /* Attestation */

    mbedtls_pk_context  pk_ctx;
    uint8_t     sign[U2F_SIGNDER_MAX_SIZE];
    size_t      len;
    uint16_t    fido_key_size;
    uint8_t     *fido_key = device_get_fido_key(&fido_key_size);

#if 1
    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(&pk_ctx, fido_key, fido_key_size, NULL, 0);
    mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256, buffer, mbedtls_md_get_size(md_info), sign, &len, device_mbedtls_rng, NULL);
    mbedtls_pk_free(&pk_ctx);
#else
    mbedtls_ecdsa_context   ecdsa_ctx;

    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecp_group_load(&ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&ecdsa_ctx.d, fido_key, fido_key_size);
    mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256, buffer, mbedtls_md_get_size(md_info), sign, &len,
            device_mbedtls_rng, NULL);
    mbedtls_ecdsa_free(&ecdsa_ctx);
#endif

    /* response */

    uint16_t    fido_cert_size;
    uint8_t     *fido_cert = device_get_fido_cert(&fido_cert_size);

    hidif_add_byte(0x05);                               // reserved
    hidif_add_bytes(publ_key, U2F_PUBL_KEY_SIZE);       // ECC public key of uncompressed form (RFC5480 section-2.2)
    hidif_add_byte(sizeof(U2fKey));
    hidif_add_bytes(this->key_handle_.key_, U2F_KEY_SIZE);
    hidif_add_bytes(this->key_handle_.tag_, U2F_TAG_SIZE);
    hidif_add_bytes(fido_cert, fido_cert_size);
    hidif_add_bytes(sign, len);

    hidif_append_sw(FIDO_SW_NO_ERROR);
    process_term(this);
}

static void try_authenticate(U2fData *this, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    if (param_parser(dat, this->appl_param_, this->chal_param_, &this->key_handle_))
    {
        U2fKey  cmp_key;

        memcpy(cmp_key.key_, this->key_handle_.key_, U2F_KEY_SIZE);
        make_u2f_tag(this->appl_param_, &cmp_key);

        if (memcmp(cmp_key.tag_, this->key_handle_.tag_, U2F_TAG_SIZE) == 0)
        {
            uint8_t     pin_command[5] = { PIN_CLASS, PIN_INS_CHECK, 0, 0, 0 };

            pin_postman(this->cid_, pin_command, 5, now_ms);

            this->status_       = _Authentication_;
            this->keepalive_ms_ = now_ms + U2F_KEEPALIVE_INTERVAL_MS;
            this->timeout_ms_   = now_ms + U2F_TIMEOUT_MS;
        }
        else
        {
            hidif_append_sw(FIDO_SW_WRONG_DATA);
            process_term(this);
        }
    }
    else
    {
        hidif_append_sw(FIDO_SW_WRONG_DATA);
        process_term(this);
    }
}

static void lease_authenticate(U2fData *this)
{
    const uint8_t   user_present = 1;
    uint8_t     priv_key[U2F_PRIV_KEY_SIZE];
    uint32_t    count = device_get_counter();
    uint8_t     bs_cnt[4];

    bs_cnt[0] = count >> 24 & 0xFF;
    bs_cnt[1] = count >> 16 & 0xFF;
    bs_cnt[2] = count >>  8 & 0xFF;
    bs_cnt[3] = count >>  0 & 0xFF;

    /* hash */

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;
    uint8_t     buffer[mbedtls_md_get_size(md_info)];

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);

    mbedtls_md_update(&md_ctx, this->appl_param_, U2F_APPL_PARAM_SIZE);
    mbedtls_md_update(&md_ctx, &user_present, 1);   // user present
    mbedtls_md_update(&md_ctx, bs_cnt, 4);          // counter
    mbedtls_md_update(&md_ctx, this->chal_param_, U2F_CHAL_PARAM_SIZE);

    mbedtls_md_finish(&md_ctx, buffer);
    mbedtls_md_free(&md_ctx);

    /* key generation */

    make_keypair(this->appl_param_, &this->key_handle_, priv_key, NULL);

    /* sign */

    mbedtls_ecdsa_context   ecdsa_ctx;
    uint8_t     sign[U2F_SIGNDER_MAX_SIZE];
    size_t      len;

    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecp_group_load(&ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&ecdsa_ctx.d, priv_key, U2F_PRIV_KEY_SIZE);
    mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256, buffer, mbedtls_md_get_size(md_info), sign, &len,
            device_mbedtls_rng, NULL);
    mbedtls_ecdsa_free(&ecdsa_ctx);

    /* response */

    hidif_add_byte(user_present);
    hidif_add_bytes(bs_cnt, 4);
    hidif_add_bytes(sign, len);

    hidif_append_sw(FIDO_SW_NO_ERROR);
    process_term(this);
}

static bool wakeup_func(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    U2fData *this = (U2fData*)param;
    bool    wakeup = false;

    switch (this->status_)
    {
    case _Registration_:
    case _Authentication_:

        if (!process_timeout(this, now_ms))
        {
            if (status_get() == _AppStatus_Idle_)
            {
                wakeup = true;
            }
            else if (now_ms > this->keepalive_ms_)
            {
                hidif_add_byte(KEEPALIVE_TUP_NEEDED);
                hidif_write(this->cid_, HIDIF_KEEPALIVE);

                this->keepalive_ms_ = now_ms + U2F_KEEPALIVE_INTERVAL_MS;
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
    U2fData *this = (U2fData*)param;

    if (this->status_ == _Registration_)
    {
        if (device_get_info()->pin_confirmed_)
        {
            lease_registration(this);
        }
        else
        {
            hidif_append_sw(FIDO_SW_CONDITINOS_NOT_SATISFIED);
            process_term(this);
        }
    }
    else if (this->status_ == _Authentication_)
    {
        if (device_get_info()->pin_confirmed_)
        {
            lease_authenticate(this);
        }
        else
        {
            hidif_append_sw(FIDO_SW_CONDITINOS_NOT_SATISFIED);
            process_term(this);
        }
    }
    else
    {
        hidif_append_sw(FIDO_SW_WRONG_DATA);
        process_term(this);
    }
}

void u2f_init(void)
{
    worker_join(wakeup_func, worker_func, _WorkerPrio_UserMid_, &_u2f_data);
}

void u2f_reset(void)
{
    memset(&_u2f_data, 0, sizeof(U2fData));
}

void u2f_postman(uint32_t cid, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    U2fRequest  *request = (U2fRequest*)dat;

    device_get_info()->pin_confirmed_ = false;

    if (request->cla_ == 0)
    {
        _u2f_data.cid_ = cid;

        switch (request->ins_)
        {
        case U2F_REGISTER:

            try_registration(&_u2f_data, request->dat_, len, now_ms);
            break;

        case U2F_AUTHENTICATE:

            switch (request->p1_)
            {
            case CHECK_ONLY:
                check_registration(&_u2f_data, request->dat_, len);
                break;
            case ENFORCE_USER_PRESENCE_AND_SIGN:
            case DONT_ENFORCE_USER_PRESENCE_AND_SIGN:
                try_authenticate(&_u2f_data, request->dat_, len, now_ms);
                break;
            default:
                hidif_append_sw(FIDO_SW_WRONG_DATA);
                process_term(&_u2f_data);
                break;
            }
            break;

        case U2F_VERSION:

            if ((request->p1_ == 0) && (request->p2_ == 0))
            {
                hidif_add_bytes((uint8_t*)U2F_VERSION_STR, strlen(U2F_VERSION_STR));
                hidif_append_sw(FIDO_SW_NO_ERROR);
            }
            else
            {
                hidif_append_sw(FIDO_SW_WRONG_DATA);
            }
            process_term(&_u2f_data);
            break;

        default:

            hidif_append_sw(FIDO_SW_INS_NOT_SUPPORTED);
            process_term(&_u2f_data);
            break;
        }
    }
    else
    {
        hidif_append_sw(FIDO_SW_CLA_NOT_SUPPORTED);
        process_term(&_u2f_data);
    }
}

/* end of file ****************************************************************************************************** */
