/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "ctap2_maker.h"
#include "fidodef.h"
#include "cnm_buffer.h"
#include "app_misc.h"
#include "app_device.h"
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

static uint8_t make_attested_credential_data(CredentialId *credential_id, RelyingPartyId *rpid,
        PubKeyCredParam *cred_param, BufferHandle *bh)
{
    CoseKey         cose_key;
    CborEncoder     encoder;

    memset(&cose_key, 0, sizeof(cose_key));
    *inc_size = 0;

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

static uint8_t make_extensions(CredentialId *credential_id, ExtensionsEntity *extensions, BufferHandle *bh)
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
        uint8_t     size = mbedtls_md_get_size(md_info);
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
        mbedtls_cipher_update(&cihper_ctx, output.output1_, sizeof(output.output1_), bs, &size);
        mbedtls_cipher_finish(&cipher, bs, &size);
        memcpy(output1, bs, size);

        if (secret->salt_enc_.size_ == 64)
        {
            mbedtls_cipher_reset(&cipher_ctx);
            mbedtls_cipher_update(&cihper_ctx, output.output2_, sizeof(output.output2_), bs, &size);
            mbedtls_cipher_finish(&cipher, bs, &size);
            memcpy(output2, bs, size);
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

static uint8_t make_authenticator_data(MakeCredential *make_credential, CredentialId *credential_id, BufferHandle *bh)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    PubKeyCredParam         *credential_data = NULL;
    RelyingPartyId          *rpid = &make_credential->relying_party_.id_;
    PubKeyCredParamsEntity  *pubkey_cred = &make_credential->pubkey_cred_param_;
    ExtensionsEntity        *extensions = &make_credential->extensions_;
    uint8_t     result = FIDO_ERR_SUCCESS;
    uint8_t     bs_size = mbedtls_md_get_size(md_info);
    uint8_t     bs[bs_size];
    uint8_t     flags = 0;
    uint16_t    used_size;

    /**
     * find to suport public key credential param if exist
     */

    for (int8_t i = 0; i < pubkey_cred->count_; i++)
    {
        if (is_support_public_key_credential_param(pubkey_cred->params_[i].type_, pubkey_cred->params_[i].alg_))
        {
            credential_data = &pubkey_cred->params_[i];
            break;
        }
    }

    /* rpidHash */

    mbedtls_md(md_info, rpid->id_, sizeof(rpid->id_), bs);

    buif_add_bytes_unsafe(bh, bs, bs_size);

    /* flags */

    flags |= 1 << 0;        // up
    if (device_get_auth()->uv_)
        flags |= 1 << 2;    // uv
    if (credential_data)
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

        if (credential_data)
        {
            result = make_attested_credential_data(credential_id, rpid, credential_data, bh);
            if (result != FIDO_ERR_SUCCESS)
                break;
        }

        /* extensions */

        if (extensions->type_ != _Extensions_None)
        {
            result = make_extensions(credential_id, extensions, bh);
            if (result != FIDO_ERR_SUCCESS)
                break;
        }
    }
    while (0);

    return result;
}

static uint8_t make_attestation_statement(uint8_t *auth_data, uint16_t auth_data_size,
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

uint8_t ctap2_maker_make_credential(MakeCredential *make_credential, CredentialId *credential_id)
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

    cbor_encoder_init(&encoder, ba_hidif.head(), ba_hidif.size(), 0);
    cbor_encoder_create_map(&encoder, &map, 3);

    do
    {
        /* authData */

        result = make_authenticator_data(make_credential, credential_id, &buffer_handle);
        if (result != FIDO_ERR_SUCCESS)
            break;

        cbor_encode_int(&map, MakeCredentialResp_authData);
        cbor_encode_byte_string(&map, buffer_handle->buffer_, buffer_handle->used_size_);

        /* fmt */

        cbor_encode_int(&map, MakeCredentialResp_fmt);
        cbor_encode_text_stringz(&map, ATTESTATION_STATEMENT_FORMAT_IDENTIFIER);

        /* attStmt */

        uint8_t     *sign_der = buffer_handle->buffer_ + buffer_handle->used_size_;
        uint8_t     sign_len;

        result = make_attestation_statement(buffer_handle->buffer_, buffer_handle->used_size_,
                &make_credential->client_data_hash_, sign_der, &sign_len);
        if (result != FIDO_ERR_SUCCESS)
            break;
        buffer_handle->used_size_ += sign_len;

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

    size_t  used_len = cbor_encoder_get_buffer_size(&encoder, ba_hidif.head());

    ba_hidif.set(used_len);

    return result;
}

/* end of file ****************************************************************************************************** */
