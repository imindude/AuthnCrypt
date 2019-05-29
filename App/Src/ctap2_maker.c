/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "ctap2_maker.h"
#include "app_misc.h"
#include "app_device.h"
#include "cnm_buffer.h"
#include "cbor.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"

/* ****************************************************************************************************************** */

static bool is_support_public_key_credential_param(int8_t type, int32_t alg)
{
    if ((type == CREDENTIAL_TYPE_publicKey) && (alg == COSE_Alg_ES256))
        return true;
    return false;
}

static void packing_cose_key(CborEncoder *encoder, CoseKey *cose_key)
{
    CborEncoder     map;

    cbor_encoder_create_map(encoder, &map, 5);

    cbor_encode_int(&map, COSE_Label_kty);
    cbor_encode_int(&map, cose_key->kty_);

    cbor_encode_int(&map, COSE_Label_alg);
    cbor_encode_int(&map, cose_key->alg_);

    cbor_encode_int(&map, COSE_Label_crv);
    cbor_encode_int(&map, cose_key->crv_);

    cbor_encode_int(&map, COSE_Label_x);
    cbor_encode_byte_string(&map, cose_key->x_, sizeof(cose_key->x_));

    cbor_encode_int(&map, COSE_Label_y);
    cbor_encode_byte_string(&map, cose_key->y_, sizeof(cose_key->y_));

    cbor_encoder_close_container(encoder, &map);
}

static uint8_t build_attested_credential_data(CredentialId *credential_id, RelyingPartyId *rpid,
        CredentialParameters *cred_param, BufferHandle *bh)
{
    CoseKey         cose_key;
    CborEncoder     encoder;

    memset(&cose_key, 0, sizeof(cose_key));

    /* aaguid */

    buif_add_bytes_unsafe(bh, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_));

    /* credentialIdLength */

    buif_add_byte_unsafe(bh, sizeof(*credential_id) >> 8 & 0xFF);
    buif_add_byte_unsafe(bh, sizeof(*credential_id) >> 0 & 0xFF);

    /* credentialId */

    buif_add_bytes_unsafe(bh, credential_id->bytes_, sizeof(*credential_id));

    /* credentialPublicKey */

    (void)cred_param;   // ???

    cose_key.kty_ = COSE_Key_EC2;
    cose_key.alg_ = COSE_Alg_ES256;
    cose_key.crv_ = COSE_Crv_P256;
    make_secp256r1_private_key(credential_id->bytes_, sizeof(*credential_id), cose_key.d_);
    make_secp256r1_public_key(cose_key.d_, cose_key.x_, cose_key.y_);

    cbor_encoder_init(&encoder, bh->buffer_ + bh->used_size_, bh->max_size_ - bh->used_size_, 0);
    packing_cose_key(&encoder, &cose_key);
    bh->used_size_ += cbor_encoder_get_buffer_size(&encoder, bh->buffer_ + bh->used_size_);

    return FIDO_ERR_SUCCESS;
}

static uint8_t build_extensions(CredentialId *credential_id, ExtensionsEntity *extensions, BufferHandle *bh)
{
    CborEncoder     encoder;
    CborEncoder     map;

    if (extensions->type_ == _HmacSecret_Create)
    {
        cbor_encoder_init(&encoder, bh->buffer_ + bh->used_size_, bh->max_size_ - bh->used_size_, 0);

        cbor_encoder_create_map(&encoder, &map, 1);
        cbor_encode_text_stringz(&map, EXTENSIONS_TYPE_HMAC_SECRET_STR);
        cbor_encode_boolean(&map, true);
        cbor_encoder_close_container(&encoder, &map);

        bh->used_size_ += cbor_encoder_get_buffer_size(&encoder, bh->buffer_ + bh->used_size_);
    }
    else if (extensions->type_ == _HmacSecret_Get)
    {
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        HmacSecret  *secret = &extensions->secret_;
        size_t      size = mbedtls_md_get_size(md_info);
        uint8_t     bs[size];
        uint8_t     shared_secret[size];
        union
        {
            struct
            {
                uint8_t output1_[sizeof(secret->salt_enc_.salt1_)];
                uint8_t output2_[sizeof(secret->salt_enc_.salt2_)];
            };
            uint8_t     output_[sizeof(secret->salt_enc_.salt_)];
        }
        output;

        /* sharedSecret */

        get_authenticator_secret(secret->key_agreement_.x_, secret->key_agreement_.y_, bs);
        mbedtls_md(md_info, bs, sizeof(bs), shared_secret);


        /* LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16) */

        mbedtls_md_hmac(md_info, shared_secret, sizeof(shared_secret), secret->salt_enc_.salt_, secret->salt_enc_.size_,
                bs);
        if (memcmp(bs, secret->salt_auth_.auth_, sizeof(secret->salt_auth_.auth_)) == 0)
            return FIDO_ERR_EXTENSION_FIRST;

        /* outputx = HMAC-SHA-256(CredRandom, saltx) */

        mbedtls_md_hmac(md_info, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_),
                credential_id->bytes_, sizeof(*credential_id), bs);
        mbedtls_md_hmac(md_info, bs, sizeof(bs), secret->salt_enc_.salt1_, sizeof(secret->salt_enc_.salt1_),
                output.output1_);
        if (secret->salt_enc_.size_ == 64)
            mbedtls_md_hmac(md_info, bs, sizeof(bs), secret->salt_enc_.salt2_, sizeof(secret->salt_enc_.salt2_),
                    output.output2_);

        /* AES256-CBC(sharedSecret, IV=0, outputx) */

        mbedtls_cipher_context_t    cipher_ctx;

        mbedtls_cipher_init(&cipher_ctx);
        mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC));
        mbedtls_cipher_setkey(&cipher_ctx, shared_secret, sizeof(shared_secret) * 8, MBEDTLS_ENCRYPT);

        mbedtls_cipher_reset(&cipher_ctx);
        mbedtls_cipher_update(&cipher_ctx, output.output1_, sizeof(output.output1_), bs, &size);
        mbedtls_cipher_finish(&cipher_ctx, bs, &size);
        memcpy(output.output1_, bs, size);

        if (secret->salt_enc_.size_ == 64)
        {
            mbedtls_cipher_reset(&cipher_ctx);
            mbedtls_cipher_update(&cipher_ctx, output.output2_, sizeof(output.output2_), bs, &size);
            mbedtls_cipher_finish(&cipher_ctx, bs, &size);
            memcpy(output.output2_, bs, size);
        }

        mbedtls_cipher_free(&cipher_ctx);

        cbor_encoder_init(&encoder, bh->buffer_ + bh->used_size_, bh->max_size_ - bh->used_size_, 0);

        cbor_encoder_create_map(&encoder, &map, 1);
        cbor_encode_text_stringz(&map, EXTENSIONS_TYPE_HMAC_SECRET_STR);
        cbor_encode_byte_string(&map, output.output_, secret->salt_enc_.size_);
        cbor_encoder_close_container(&encoder, &map);

        bh->used_size_ += cbor_encoder_get_buffer_size(&encoder, bh->buffer_ + bh->used_size_);
    }

    return FIDO_ERR_SUCCESS;
}

static uint8_t build_authenticator_data(RelyingPartyId *rpid, ExtensionsEntity *extensions,
        CredentialParameters *cred_param, CredentialId *credential_id, BufferHandle *bh)
{
    const mbedtls_md_info_t     *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t     result = FIDO_ERR_SUCCESS;
    uint8_t     bs_size = mbedtls_md_get_size(md_info);
    uint8_t     bs[bs_size];
    uint8_t     flags = 0;

    /* rpidHash */

    mbedtls_md(md_info, rpid->id_, sizeof(rpid->id_), bs);

    buif_add_bytes_unsafe(bh, bs, bs_size);

    /* flags */

    flags |= 1 << 0;        // up
    if (device_get_auth()->uv_)
        flags |= 1 << 2;    // uv
    if (cred_param)
        flags |= 1 << 6;    // at
    if (extensions->type_ != _Extensions_None)
        flags |= 1 << 7;    // ed

    buif_add_byte_unsafe(bh, flags);

    /* signCount */

    bs[0] = credential_id->count_ >> 24 & 0xFF;
    bs[1] = credential_id->count_ >> 16 & 0xFF;
    bs[2] = credential_id->count_ >>  8 & 0xFF;
    bs[3] = credential_id->count_ >>  0 & 0xFF;

    buif_add_bytes_unsafe(bh, bs, 4);

    do
    {
        /* attestedCredentialData */

        if (cred_param)
        {
            result = build_attested_credential_data(credential_id, rpid, cred_param, bh);
            if (result != FIDO_ERR_SUCCESS)
                break;
        }

        /* extensions */

        if (extensions->type_ != _Extensions_None)
        {
            result = build_extensions(credential_id, extensions, bh);
            if (result != FIDO_ERR_SUCCESS)
                break;
        }
    }
    while (0);

    return result;
}

static uint8_t build_attestation_statement(uint8_t *auth_data, uint16_t auth_data_size,
        ClientDataHashEntity *client_data_hash, uint8_t *sign_der, uint8_t *sign_len)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t    md_ctx;
    uint8_t     hash[mbedtls_md_get_size(md_info)];

    /* SHA-256(authenticatorData || clientDataHash) */

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, auth_data, auth_data_size);
    mbedtls_md_update(&md_ctx, client_data_hash->hash_, sizeof(client_data_hash->hash_));
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    /* attestation sign & something */

    *sign_len = make_attestation_sign(hash, sizeof(hash), sign_der);

    return FIDO_ERR_SUCCESS;
}

static void build_credential(CborEncoder *encoder, CredentialDescriptor *cred_desc)
{
    CborEncoder     map;
    CborEncoder     array;

    cbor_encoder_create_map(encoder, &map, 3);

    cbor_encode_text_stringz(&map, "type");
    cbor_encode_text_stringz(&map, CREDENTIAL_TYPE_PUBLIC_KEY_STR);

    cbor_encode_text_stringz(&map, "id");
    cbor_encode_byte_string(&map, cred_desc->id_.bytes_, sizeof(cred_desc->id_));

    cbor_encode_text_stringz(&map, "transports");
    cbor_encoder_create_array(&map, &array, 1);
    cbor_encode_text_stringz(&array, "usb");
    cbor_encoder_close_container(&map, &array);

    cbor_encoder_close_container(encoder, &map);
}

static void build_user(CborEncoder *encoder, CredentialUserEntity *cred_user)
{
    CborEncoder     map;
    int8_t          items = (check_array_empty(cred_user->disp_name_, sizeof(cred_user->disp_name_)) == 0) ? 1 : 2;

    cbor_encoder_create_map(encoder, &map, items);

    cbor_encode_text_stringz(&map, "id");
    cbor_encode_byte_string(&map, cred_user->id_, sizeof(cred_user->id_));

    if (items > 1)
    {
        cbor_encode_text_stringz(&map, "displayName");
        cbor_encode_text_string(&map, (char*)cred_user->disp_name_, sizeof(cred_user->disp_name_));
    }

    cbor_encoder_close_container(encoder, &map);
}

static uint8_t build_key_agreement(CborEncoder *encoder)
{
    CoseKey         cose_key;
    DeviceAuth      *dev_auth = device_get_auth();

    memset(&cose_key, 0, sizeof(cose_key));

    cose_key.kty_ = COSE_Key_EC2;
    cose_key.alg_ = COSE_Alg_HKDF256;
    cose_key.crv_ = COSE_Crv_P256;
    memcpy(cose_key.d_, dev_auth->key_agreement_pri_, sizeof(dev_auth->key_agreement_pri_));
    make_secp256r1_public_key(cose_key.d_, cose_key.x_, cose_key.y_);
    packing_cose_key(encoder, &cose_key);

    return FIDO_ERR_SUCCESS;
}

uint8_t ctap2_maker_make_credential(MakeCredential *make_credential, CredentialId *credential_id,
        uint8_t *buffer_header, uint16_t *buffer_size)
{
    uint8_t         result;
    CborEncoder     encoder;
    CborEncoder     map;
    uint8_t         ptr[2048];
    BufferHandle    buffer_handle =
    {
            .buffer_    = ptr,
            .max_size_  = sizeof(ptr),
            .used_size_ = 0
    };

    memset(ptr, 0, sizeof(ptr));

    cbor_encoder_init(&encoder, buffer_header, *buffer_size, 0);
    cbor_encoder_create_map(&encoder, &map, 3);

    do
    {
        /* authData */

        CredentialParametersList    *cred_param_list = &make_credential->cred_param_list_;
        CredentialParameters        *cred_param = NULL;

        /**
         * find to suport public key credential param if exist
         */

        for (int8_t i = 0; i < cred_param_list->count_; i++)
        {
            if (is_support_public_key_credential_param(cred_param_list->params_[i].type_, cred_param_list->params_[i].alg_))
            {
                cred_param = &cred_param_list->params_[i];
                break;
            }
        }

        result = build_authenticator_data(&make_credential->relying_party_.id_, &make_credential->extensions_,
                cred_param, credential_id, &buffer_handle);
        if (result != FIDO_ERR_SUCCESS)
            break;

        cbor_encode_int(&map, MakeCredentialResp_authData);
        cbor_encode_byte_string(&map, buffer_handle.buffer_, buffer_handle.used_size_);

        /* fmt */

        cbor_encode_int(&map, MakeCredentialResp_fmt);
        cbor_encode_text_stringz(&map, ATTESTATION_STATEMENT_FORMAT_IDENTIFIER);

        /* attStmt */

        uint8_t     *sign_der = buffer_handle.buffer_ + buffer_handle.used_size_;
        uint8_t     sign_len;

        result = build_attestation_statement(buffer_handle.buffer_, buffer_handle.used_size_,
                &make_credential->client_data_hash_, sign_der, &sign_len);
        if (result != FIDO_ERR_SUCCESS)
            break;
        buffer_handle.used_size_ += sign_len;

        CborEncoder     sub_map;
        CborEncoder     array;
        uint16_t        fido_key_size;
        uint8_t         *fido_key = device_get_fido_key(&fido_key_size);

        cbor_encode_int(&map, MakeCredentialResp_attStmt);
        cbor_encoder_create_map(&map, &sub_map, 3);

        /* attestation statement format */

        cbor_encode_text_stringz(&sub_map, "alg");
        cbor_encode_int(&sub_map, COSE_Alg_ES256);

        cbor_encode_text_stringz(&sub_map, "sig");
        cbor_encode_byte_string(&sub_map, sign_der, sign_len);

        cbor_encode_text_stringz(&sub_map, "x5c");
        cbor_encoder_create_array(&sub_map, &array, 1);
        cbor_encode_byte_string(&array, fido_key, fido_key_size);
        cbor_encoder_close_container(&sub_map, &array);

        cbor_encoder_close_container(&map, &sub_map);
    }
    while (0);

    cbor_encoder_close_container(&encoder, &map);
    *buffer_size = cbor_encoder_get_buffer_size(&encoder, buffer_header);

    return result;
}

uint8_t ctap2_maker_get_assertion(GetAssertion *get_assertion, CredentialList *cred_list, int8_t credential_count,
        uint8_t *buffer_header, uint16_t *buffer_size)
{
    uint8_t         result;
    CborEncoder     encoder;
    CborEncoder     map;
    uint8_t         ptr[2048];
    BufferHandle    buffer_handle =
    {
            .buffer_    = ptr,
            .max_size_  = sizeof(ptr),
            .used_size_ = 0
    };

    memset(ptr, 0, sizeof(ptr));

    cbor_encoder_init(&encoder, buffer_header, *buffer_size, 0);
    cbor_encoder_create_map(&encoder, &map, 5);

    do
    {
        int8_t      credential_index = cred_list->count_ - credential_count;
        CredentialDescriptor    *cred_desc = &cred_list->credentials_[credential_index].desc_;
        CredentialUserEntity    *cred_user = &cred_list->credentials_[credential_index].user_;

        /* credential */

        cbor_encode_int(&map, GetAssertionResp_credential);
        build_credential(&map, cred_desc);

        /* authData */

        result = build_authenticator_data(&get_assertion->rp_id_, &get_assertion->extensions_, NULL, &cred_desc->id_,
                &buffer_handle);
        if (result != FIDO_ERR_SUCCESS)
            break;

        cbor_encode_int(&map, GetAssertionResp_authData);
        cbor_encode_byte_string(&map, buffer_handle.buffer_, buffer_handle.used_size_);

        /* signature */

        uint8_t     *sign_der = buffer_handle.buffer_ + buffer_handle.used_size_;
        uint8_t     sign_len;

        result = build_attestation_statement(buffer_handle.buffer_, buffer_handle.used_size_,
                &get_assertion->client_data_hash_, sign_der, &sign_len);
        if (result != FIDO_ERR_SUCCESS)
            break;
        buffer_handle.used_size_ += sign_len;

        cbor_encode_int(&map, GetAssertionResp_signature);
        cbor_encode_byte_string(&map, sign_der, sign_len);

        /* user */

        cbor_encode_int(&map, GetAssertionResp_user);
        build_user(&map, cred_user);

        /* numberOfCredentials */

        cbor_encode_int(&map, GetAssertionResp_numberOfCredentials);
        cbor_encode_int(&map, cred_list->count_);
    }
    while (0);

    cbor_encoder_close_container(&encoder, &map);
    *buffer_size = cbor_encoder_get_buffer_size(&encoder, buffer_header);

    return result;
}

uint8_t ctap2_maker_get_info(uint8_t *buffer_header, uint16_t *buffer_size)
{
    CborEncoder     encoder;
    CborEncoder     map;

    cbor_encoder_init(&encoder, buffer_header, *buffer_size, 0);
    cbor_encoder_create_map(&encoder, &map, 6);

    do
    {
        CborEncoder array;
        CborEncoder sub_map;

        /* version */

        cbor_encode_int(&map, GetInfoResp_versions);
        cbor_encoder_create_array(&map, &array, 1);
        cbor_encode_text_stringz(&array, CTAP2_VERSION_STR);
        cbor_encoder_close_container(&map, &array);

        /* extensions */

        cbor_encode_int(&map, GetInfoResp_extensions);
        cbor_encoder_create_array(&map, &array, 1);
        cbor_encode_text_stringz(&array, EXTENSIONS_TYPE_HMAC_SECRET_STR);
        cbor_encoder_close_container(&map, &array);

        /* aaguid */

        cbor_encode_int(&map, GetInfoResp_aaguid);
        cbor_encode_byte_string(&map, device_get_info()->uid_.bytes_, sizeof(device_get_info()->uid_.bytes_));

        /* options */

        cbor_encode_int(&map, GetInfoResp_options);
        cbor_encoder_create_map(&map, &sub_map, 5);

        cbor_encode_text_stringz(&sub_map, "plat");
        cbor_encode_boolean(&sub_map, false);
        cbor_encode_text_stringz(&sub_map, "rk");
        cbor_encode_boolean(&sub_map, true);
        cbor_encode_text_stringz(&sub_map, "clientPin");
        cbor_encode_boolean(&sub_map, device_get_auth()->client_pin_);
        cbor_encode_text_stringz(&sub_map, "up");
        cbor_encode_boolean(&sub_map, true);
        cbor_encode_text_stringz(&sub_map, "uv");
        cbor_encode_boolean(&sub_map, false);

        cbor_encoder_close_container(&map, &sub_map);

        /* maxMsgSize */

        cbor_encode_int(&map, GetInfoResp_maxMsgSize);
        cbor_encode_uint(&map, ba_hidif.size());

        /* pinProtocols */

        cbor_encode_int(&map, GetInfoResp_pinProtocols);
        cbor_encoder_create_array(&map, &array, 1);
        cbor_encode_uint(&array, FIDO2_PIN_PROTOCOL_VER);
        cbor_encoder_close_container(&map, &array);
    }
    while (0);

    cbor_encoder_close_container(&encoder, &map);
    *buffer_size = cbor_encoder_get_buffer_size(&encoder, buffer_header);

    return FIDO_ERR_SUCCESS;
}

static uint8_t build_set_refresh_pin(KeyAgreementEntity *key_agreement, PinAuthEntity *pin_auth,
        NewPinEncEntity *pin_enc, PinHashEncEntity *pin_hash)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t     result = FIDO_ERR_SUCCESS;
    size_t      size = mbedtls_md_get_size(md_info);
    uint8_t     bytes[256];
    uint8_t     shared_secret[size];
    uint8_t     new_pin[PIN_MAX_LEN];
    int16_t     pin_len;

    memset(new_pin, 0, sizeof(new_pin));

    /* SHA-256((baG).x) */

    get_authenticator_secret(key_agreement->key_.x_, key_agreement->key_.y_, bytes);
    mbedtls_md(md_info, bytes, sizeof(shared_secret), shared_secret);

    do
    {
        mbedtls_md_context_t    md_ctx;

        /* HMAC-SHA-256(sharedSecret, newPinEnc) or HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc) */

        mbedtls_md_init(&md_ctx);
        mbedtls_md_setup(&md_ctx, md_info, 1);
        mbedtls_md_hmac_starts(&md_ctx, shared_secret, sizeof(shared_secret));
        if (pin_hash)
            mbedtls_md_hmac_update(&md_ctx, pin_hash->enc_, pin_hash->len_);
        mbedtls_md_hmac_finish(&md_ctx, bytes);

        if (memcmp(bytes, pin_auth->auth_, sizeof(pin_auth->auth_)) != 0)
        {
            result = FIDO_ERR_PIN_AUTH_INVALID;
            break;
        }

        /* AES256-CBC(sharedSecret, IV=0, newPin) */

        mbedtls_cipher_context_t    cipher_ctx;

        mbedtls_cipher_init(&cipher_ctx);
        mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC));
        mbedtls_cipher_setkey(&cipher_ctx, shared_secret, sizeof(shared_secret) * 8, MBEDTLS_DECRYPT);
        mbedtls_cipher_reset(&cipher_ctx);
        mbedtls_cipher_update(&cipher_ctx, pin_enc->enc_, pin_enc->len_, bytes, &size);
        mbedtls_cipher_finish(&cipher_ctx, new_pin, &size);
        mbedtls_cipher_free(&cipher_ctx);

        pin_len = check_array_empty(new_pin, size);
        if (pin_len < PIN_MIN_LEN)
        {
            result = FIDO_ERR_PIN_POLICY_VIOLATION;
            break;
        }

        if (pin_hash)
        {
            mbedtls_cipher_init(&cipher_ctx);
            mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC));
            mbedtls_cipher_setkey(&cipher_ctx, shared_secret, sizeof(shared_secret) * 8, MBEDTLS_DECRYPT);
            mbedtls_cipher_reset(&cipher_ctx);
            mbedtls_cipher_update(&cipher_ctx, pin_hash->enc_, 16, bytes, &size);
            mbedtls_cipher_finish(&cipher_ctx, bytes, &size);
            mbedtls_cipher_free(&cipher_ctx);

            if (memcmp(bytes, device_get_auth()->pin_hash_, 16) != 0)
            {
                result = FIDO_ERR_PIN_AUTH_INVALID;
                break;
            }
        }
    }
    while (0);

    if (result == FIDO_ERR_SUCCESS)
    {
        // save password
        memset(device_get_auth()->pin_code_, 0, sizeof(device_get_auth()->pin_code_));
        memcpy(device_get_auth()->pin_code_, new_pin, pin_len);
    }

    return result;
}

static uint8_t build_pin_token(KeyAgreementEntity *key_agreement, PinHashEncEntity *pin_hash, BufferHandle *bh)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t     result = FIDO_ERR_SUCCESS;
    size_t      size = mbedtls_md_get_size(md_info);
    uint8_t     bytes[size];
    uint8_t     shared_secret[size];

    /* SHA-256((baG).x) */

    get_authenticator_secret(key_agreement->key_.x_, key_agreement->key_.y_, bytes);
    mbedtls_md(md_info, bytes, sizeof(shared_secret), shared_secret);

    do
    {
        mbedtls_cipher_context_t    cipher_ctx;

        mbedtls_cipher_init(&cipher_ctx);
        mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC));
        mbedtls_cipher_setkey(&cipher_ctx, shared_secret, sizeof(shared_secret) * 8, MBEDTLS_DECRYPT);
        mbedtls_cipher_reset(&cipher_ctx);
        mbedtls_cipher_update(&cipher_ctx, pin_hash->enc_, 16, bytes, &size);
        mbedtls_cipher_finish(&cipher_ctx, bytes, &size);
        mbedtls_cipher_free(&cipher_ctx);

        if (memcmp(bytes, device_get_auth()->pin_hash_, 16) != 0)
        {
            result = FIDO_ERR_PIN_AUTH_INVALID;
            break;
        }

        mbedtls_cipher_init(&cipher_ctx);
        mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC));
        mbedtls_cipher_setkey(&cipher_ctx, shared_secret, sizeof(shared_secret) * 8, MBEDTLS_ENCRYPT);
        mbedtls_cipher_reset(&cipher_ctx);
        mbedtls_cipher_update(&cipher_ctx, device_get_auth()->pin_token_, sizeof(device_get_auth()->pin_token_), bytes,
                &size);
        mbedtls_cipher_finish(&cipher_ctx, bytes, &size);
        mbedtls_cipher_free(&cipher_ctx);

        buif_add_bytes_unsafe(bh, bytes, size);
    }
    while (0);

    return result;
}

uint8_t ctap2_maker_client_pin(ClientPin *client_pin, uint8_t *buffer_header, uint16_t *buffer_size)
{
    uint8_t         result = FIDO_ERR_SUCCESS;
    CborEncoder     encoder;
    CborEncoder     map;
    uint8_t         ptr[256];
    BufferHandle    buffer_handle =
    {
            .buffer_    = ptr,
            .max_size_  = sizeof(ptr),
            .used_size_ = 0
    };

    memset(ptr, 0, sizeof(ptr));

    cbor_encoder_init(&encoder, buffer_header, *buffer_size, 0);
    cbor_encoder_create_map(&encoder, &map, 1);

    switch (client_pin->sub_command_.command_)
    {
    case ClientPIN_SubCommand_getRetries:

        cbor_encode_int(&map, ClientPIN_Resp_retries);
        cbor_encode_uint(&map, device_get_auth()->retry_pin_);
        break;

    case ClientPIN_SubCommand_getKeyAgreement:

        cbor_encode_int(&map, ClientPIN_Resp_keyAgreement);
        result = build_key_agreement(&map);
        break;

    case ClientPIN_SubCommand_setPIN:

        result = build_set_refresh_pin(&client_pin->key_agreement_, &client_pin->pin_auth_,
                &client_pin->new_pin_enc_, NULL);
        break;

    case ClientPIN_SubCommand_changePIN:

        result = build_set_refresh_pin(&client_pin->key_agreement_, &client_pin->pin_auth_,
                &client_pin->new_pin_enc_, &client_pin->pin_hash_enc_);
        break;

    case ClientPIN_SubCommand_getPINToken:

        result = build_pin_token(&client_pin->key_agreement_, &client_pin->pin_hash_enc_, &buffer_handle);
        break;

    default:

        break;
    }

    cbor_encoder_close_container(&encoder, &map);
    *buffer_size = cbor_encoder_get_buffer_size(&encoder, buffer_header);

    return result;
}

/* end of file ****************************************************************************************************** */
