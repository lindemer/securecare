/**
 * Copyright (c) 2020, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 **/

#include "cose.h"

#define RETURN_ERROR(x) err = x; if (err) return err;

#define HASH_TSTR(ctx, nc, buf, len_buf, str)                                  \
    nanocbor_encoder_init(&nc, buf, len_buf);                                  \
    nanocbor_fmt_tstr(&nc, strlen((const char *) str));                        \
    cose_hash_update(ctx, buf, nanocbor_encoded_len(&nc));                     \
    cose_hash_update(ctx, str, strlen((const char *) str));

#define HASH_BSTR(ctx, nc, buf, len_buf, bstr, len_bstr)                       \
    nanocbor_encoder_init(&nc, buf, len_buf);                                  \
    nanocbor_fmt_bstr(&nc, len_bstr);                                          \
    cose_hash_update(ctx, buf, nanocbor_encoded_len(&nc));                     \
    cose_hash_update(ctx, bstr, len_bstr);

/*******************************************************************************
 * @section Miscellaneous (private)
 ******************************************************************************/

int _cose_encode_protected(cose_key_t * key, nanocbor_encoder_t * nc)
{
    nanocbor_fmt_map(nc, 1);
    nanocbor_fmt_int(nc, cose_header_algorithm);
    nanocbor_fmt_int(nc, key->alg);
    return nanocbor_encoded_len(nc);
}

/*******************************************************************************
 * @section Miscellaneous (public)
 ******************************************************************************/

inline void cose_set_kid(cose_key_t * key, const uint8_t * kid, size_t len_kid)
{
    key->kid = kid;
    key->len_kid = len_kid;
}

inline void cose_set_aad(cose_key_t * key, const uint8_t * aad, size_t len_aad)
{
    key->aad = aad;
    key->len_aad = len_aad;
}

/*******************************************************************************
 * @section Generic cryptographic message digest API (public)
 ******************************************************************************/

int cose_hash_init(cose_hash_context_t * ctx)
{
    int err;
#ifdef COSE_BACKEND_NRF
    if ((ctx->type) != (COSE_SHA256_TYPE)) return COSE_ERROR_UNSUPPORTED;
    RETURN_ERROR(nrf_crypto_hash_init(&ctx->ctx, 
                &g_nrf_crypto_hash_sha256_info));
#else
    RETURN_ERROR(mbedtls_md_setup(&ctx->ctx, 
                mbedtls_md_info_from_type(ctx->type), 0));
    RETURN_ERROR(mbedtls_md_starts(&ctx->ctx));
#endif
    return COSE_ERROR_NONE;
}

int cose_hash_update(cose_hash_context_t * ctx, 
        const uint8_t * data, const size_t len)
{
#ifdef COSE_BACKEND_NRF
    nrf_crypto_hash_update(&ctx->ctx, data, len);
#else
    mbedtls_md_update(&ctx->ctx, data, len);
#endif
    return COSE_ERROR_NONE;
}

int cose_hash_finish(cose_hash_context_t * ctx)
{
    int err;
#ifdef COSE_BACKEND_NRF
    RETURN_ERROR(nrf_crypto_hash_finalize(&ctx->ctx, ctx->hash, &ctx->len));
#else
    RETURN_ERROR(mbedtls_md_finish(&ctx->ctx, ctx->hash));
    if (ctx->type != COSE_SHA256_TYPE) return COSE_ERROR_UNSUPPORTED;
    ctx->len = COSE_SHA256_LENGTH;
#endif
    return COSE_ERROR_NONE;
}

int cose_hash(cose_hash_context_t * ctx,
        const uint8_t * data, const size_t len)
{
    int err;
#ifdef COSE_BACKEND_NRF
    if ((ctx->type) != (COSE_SHA256_TYPE)) return COSE_ERROR_UNSUPPORTED;
    RETURN_ERROR(nrf_crypto_hash_calculate(&ctx->ctx, 
                &g_nrf_crypto_hash_sha256_info, 
                data, len, ctx->hash, &ctx->len));
#else
    RETURN_ERROR(mbedtls_md(mbedtls_md_info_from_type(ctx->type), data, len, 
                ctx->hash))
    if (ctx->type != COSE_SHA256_TYPE) return COSE_ERROR_UNSUPPORTED;
    ctx->len = COSE_SHA256_LENGTH;
#endif
    return COSE_ERROR_NONE;
}

/*******************************************************************************
 * @section COSE Sign1 (private)
 ******************************************************************************/

int _cose_sign1_hash(cose_sign_context_t * ctx,
        const uint8_t *pld, const size_t len_pld)
{
    cose_hash_init(&ctx->hash);
    nanocbor_encoder_t nc;

    /* serialize body_protected */
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = _cose_encode_protected(&ctx->key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    _cose_encode_protected(&ctx->key, &nc);

    /* compute length of Sig_structure */
    nanocbor_encoder_init(&nc, NULL, 0);
    nanocbor_fmt_array(&nc, 4);
    nanocbor_put_tstr(&nc, COSE_CONTEXT_SIGN1);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_put_bstr(&nc, ctx->key.aad, ctx->key.len_aad);
    nanocbor_put_bstr(&nc, pld, len_pld);
    size_t len_str = nanocbor_encoded_len(&nc);

    /* serialize and hash ToBeSigned */
    size_t len_buf = 8;
    uint8_t buf[len_buf];

    nanocbor_encoder_init(&nc, buf, len_buf);
    nanocbor_fmt_bstr(&nc, len_str);
    nanocbor_fmt_array(&nc, 4);
    cose_hash_update(&ctx->hash, buf, nanocbor_encoded_len(&nc));

    HASH_TSTR(&ctx->hash, nc, buf, len_buf, 
            (const unsigned char *) COSE_CONTEXT_SIGN1)
    HASH_BSTR(&ctx->hash, nc, buf, len_buf, prot, len_prot)
    HASH_BSTR(&ctx->hash, nc, buf, len_buf, ctx->key.aad, ctx->key.len_aad)
    HASH_BSTR(&ctx->hash, nc, buf, len_buf, pld, len_pld)

    return cose_hash_finish(&ctx->hash);
}

int _cose_sign1_encode(
        cose_sign_context_t * ctx,
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj) 
{
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = _cose_encode_protected(&ctx->key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    _cose_encode_protected(&ctx->key, &nc);

    nanocbor_encoder_init(&nc, obj, *len_obj);
    nanocbor_fmt_tag(&nc, cose_tag_sign1);
    nanocbor_fmt_array(&nc, 4);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_fmt_map(&nc, 0);
    nanocbor_put_bstr(&nc, pld, len_pld);
    nanocbor_put_bstr(&nc, ctx->sig, ctx->len_sig);
    *len_obj = nanocbor_encoded_len(&nc);

    return COSE_ERROR_NONE;
}

int _cose_sign1_decode(
        cose_sign_context_t * ctx,
        const uint8_t * obj, const size_t len_obj,
        const uint8_t ** pld, size_t * len_pld)
{
    nanocbor_value_t nc, arr;
    nanocbor_decoder_init(&nc, obj, len_obj);
    nanocbor_skip(&nc);
    if (nanocbor_enter_array(&nc, &arr) < 0) return COSE_ERROR_DECODE;
    nanocbor_skip(&arr);
    nanocbor_skip(&arr);
    nanocbor_get_bstr(&arr, pld, len_pld); 

    _cose_sign1_hash(ctx, *pld, *len_pld);
    nanocbor_get_bstr(&arr, (const uint8_t **) &ctx->sig, &ctx->len_sig); 

    return COSE_ERROR_NONE;
}

/*******************************************************************************
 * @section COSE Sign1 (public)
 ******************************************************************************/

#ifdef COSE_BACKEND_NRF
int cose_sign_raw_init(cose_sign_context_t * ctx, cose_mode_t mode, 
        const uint8_t * key, size_t len_key)
{
    /**
     * The user must supply the curve and algorithm to initialize a raw key. 
     * This information cannot be derived from the key's byte string.
     */

    if (ctx->key.curve != cose_curve_p256) return COSE_ERROR_UNSUPPORTED;
    if (ctx->key.alg != cose_alg_ecdsa_sha_256) return COSE_ERROR_UNSUPPORTED;

    ctx->len_sig = COSE_P256_KEY_LENGTH * 2;
    ctx->hash.len = COSE_SHA256_LENGTH;
    ctx->hash.type = COSE_SHA256_TYPE;

    int err;
    if (mode == cose_mode_r) {
        ctx->key.op = cose_key_op_verify;
        RETURN_ERROR(nrf_crypto_ecc_public_key_from_raw(
                    &g_nrf_crypto_ecc_secp256r1_curve_info,
                    &ctx->ctx.pub, key, len_key));
    
    } else return COSE_ERROR_UNSUPPORTED;

    ctx->key.kid = NULL;
    ctx->key.len_kid = 0;
    ctx->key.aad = NULL;
    ctx->key.len_aad = 0;

    return COSE_ERROR_NONE;
}
#else
int cose_sign_pem_init(cose_sign_context_t * ctx, cose_mode_t mode, 
        const char * pem) 
{
    mbedtls_pk_init(&ctx->ctx);

    /**
     * mbedTLS can interpret most key details from a PEM file, but the user
     * must indicate whether a public or a private key is being parsed.
     */

    int err;
    if (mode == cose_mode_r) {
        ctx->key.op = cose_key_op_verify;
        RETURN_ERROR(mbedtls_pk_parse_public_key(&ctx->ctx, 
                    (const unsigned char *) pem, strlen(pem) + 1)); 

    } else if (mode == cose_mode_w) {
        ctx->key.op = cose_key_op_sign;
        RETURN_ERROR(mbedtls_pk_parse_key(&ctx->ctx, 
                    (const unsigned char *) pem, strlen(pem) + 1, NULL, 0));

    } else return COSE_ERROR_UNSUPPORTED;

    mbedtls_ecp_group_id grp_id = mbedtls_pk_ec(ctx->ctx)->grp.id;
    if (grp_id != MBEDTLS_ECP_DP_SECP256R1) return COSE_ERROR_UNSUPPORTED;
        
    ctx->key.kty = cose_kty_ec2;
    ctx->len_sig = COSE_P256_KEY_LENGTH * 2;
    ctx->hash.len = COSE_SHA256_LENGTH;
    ctx->hash.type = COSE_SHA256_TYPE;
    ctx->key.curve = cose_curve_p256;
    ctx->key.alg = cose_alg_ecdsa_sha_256;
    ctx->key.kid = NULL;
    ctx->key.len_kid = 0;
    ctx->key.aad = NULL;
    ctx->key.len_aad = 0;

    return COSE_ERROR_NONE;
}
#endif /* COSE_BACKEND_NRF */

int cose_sign1_write(cose_sign_context_t * ctx, 
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj) 
{
    uint8_t signature[ctx->len_sig];
    ctx->sig = signature;

    _cose_sign1_hash(ctx, pld, len_pld);

    int err;
#ifdef COSE_BACKEND_NRF

    RETURN_ERROR(nrf_crypto_ecdsa_sign(NULL, &ctx->ctx.priv, ctx->hash.hash,
                ctx->hash.len, ctx->sig, &ctx->len_sig));

#else

    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_ecdsa_context * ecdsa = ctx->ctx.pk_ctx;
    RETURN_ERROR(mbedtls_ecdsa_sign_det(&ecdsa->grp, &r, &s, &ecdsa->d,
                ctx->hash.hash, ctx->hash.len, ctx->hash.type));
    RETURN_ERROR(mbedtls_mpi_write_binary(&r, ctx->sig, COSE_P256_KEY_LENGTH));
    RETURN_ERROR(mbedtls_mpi_write_binary(&s, ctx->sig + COSE_P256_KEY_LENGTH,
            COSE_P256_KEY_LENGTH));
     
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    ctx->len_sig = COSE_P256_KEY_LENGTH * 2;

#endif
    if (_cose_sign1_encode(ctx, pld, len_pld, obj, len_obj))
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_sign1_read(cose_sign_context_t * ctx, 
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t ** pld, size_t * len_pld) 
{
    if (_cose_sign1_decode(ctx, obj, len_obj, pld, len_pld))
        return COSE_ERROR_DECODE;

    int err;
#ifdef COSE_BACKEND_NRF

    RETURN_ERROR(nrf_crypto_ecdsa_verify(NULL, &ctx->ctx.pub, ctx->hash.hash,
                ctx->hash.len, ctx->sig, ctx->len_sig));

#else

    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_ecdsa_context * ecdsa = ctx->ctx.pk_ctx;

    RETURN_ERROR(mbedtls_mpi_read_binary(&r, ctx->sig, COSE_P256_KEY_LENGTH));
    RETURN_ERROR(mbedtls_mpi_read_binary(&s, ctx->sig + COSE_P256_KEY_LENGTH,
            COSE_P256_KEY_LENGTH));
    RETURN_ERROR(mbedtls_ecdsa_verify(&ecdsa->grp, ctx->hash.hash, 
                ctx->hash.len, &ecdsa->Q, &r, &s));
     
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

#endif
    return COSE_ERROR_NONE;
}

void cose_sign_free(cose_sign_context_t * ctx) 
{
#ifdef COSE_BACKEND_NRF
    switch (ctx->mode) {
        case (cose_mode_w):
            nrf_crypto_ecc_private_key_free(&ctx->ctx.priv); break;
        case (cose_mode_r):
            nrf_crypto_ecc_public_key_free(&ctx->ctx.pub); break;
    }
#else
    mbedtls_pk_free(&ctx->ctx);
#endif
}

/*******************************************************************************
 * @section COSE Encrypt0 (private)
 ******************************************************************************/

#ifndef COSE_BACKEND_NRF
int _cose_encrypt(
        cose_aead_context_t * ctx,
        const uint8_t * pld, const size_t len_pld,
        const uint8_t * tbe, const size_t len_tbe,
        uint8_t * enc) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {

        if (mbedtls_gcm_crypt_and_tag(&ctx->ctx, MBEDTLS_GCM_ENCRYPT, len_pld,
                    ctx->iv, ctx->len_iv, tbe, len_tbe, pld, enc, ctx->len_mac,
                    enc + len_pld))
            return COSE_ERROR_ENCRYPT;

    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int _cose_decrypt(
        cose_aead_context_t * ctx,
        const uint8_t * enc, const size_t len_enc,
        const uint8_t * tbe, const size_t len_tbe,
        uint8_t * pld, size_t * len_pld) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {

        *len_pld = len_enc - ctx->len_mac;
        if (mbedtls_gcm_auth_decrypt(&ctx->ctx, *len_pld, ctx->iv, ctx->len_iv,
                    tbe, len_tbe, enc + *len_pld, ctx->len_mac, enc, pld))
            return COSE_ERROR_DECRYPT;
            
    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int _cose_encrypt0_encode(
        cose_aead_context_t * ctx,
        const uint8_t * enc, const size_t len_enc, 
        uint8_t * obj, size_t * len_obj) 
{
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = _cose_encode_protected(&ctx->key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    _cose_encode_protected(&ctx->key, &nc);

    nanocbor_encoder_init(&nc, obj, *len_obj);
    nanocbor_fmt_tag(&nc, cose_tag_encrypt0);
    nanocbor_fmt_array(&nc, 3);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_fmt_map(&nc, 2);
    nanocbor_fmt_int(&nc, cose_header_kid);
    nanocbor_put_bstr(&nc, ctx->key.kid, ctx->key.len_kid);
    nanocbor_fmt_int(&nc, cose_header_iv);
    nanocbor_put_bstr(&nc, ctx->iv, ctx->len_iv);
    nanocbor_put_bstr(&nc, enc, len_enc);

    *len_obj = nanocbor_encoded_len(&nc);
    return COSE_ERROR_NONE;
} 

int _cose_encrypt0_decode(
        cose_aead_context_t * ctx,
        const uint8_t * obj, const size_t len_obj,
        const uint8_t ** enc, size_t * len_enc)
{
    nanocbor_value_t nc, arr, map;
    nanocbor_decoder_init(&nc, obj, len_obj);
    nanocbor_skip(&nc);
    if (nanocbor_enter_array(&nc, &arr) < 0) return COSE_ERROR_DECODE;
    nanocbor_skip(&arr); 
    if (nanocbor_enter_map(&arr, &map) < 0) return COSE_ERROR_DECODE;

    while (!nanocbor_at_end(&map)) {
        int32_t map_key;
        if (nanocbor_get_int32(&map, &map_key) < 0) return COSE_ERROR_DECODE;
        if (map_key == cose_header_iv) {
            if (nanocbor_get_bstr(
                        &map, (const uint8_t **) &ctx->iv, &ctx->len_iv) < 0)
                return COSE_ERROR_DECODE;
            else break;
        }
        nanocbor_skip(&map); 
    }

    nanocbor_skip(&arr); 
    if (nanocbor_get_bstr(&arr, enc, len_enc) < 0) return COSE_ERROR_DECODE;

    return COSE_ERROR_NONE;
}

int _cose_encrypt0_tbe(
        cose_key_t * key,
        uint8_t * tbe, size_t * len_tbe)
{
    /* serialize protected */
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = _cose_encode_protected(key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    _cose_encode_protected(key, &nc);
   
    /* get size of Enc_structure */
    nanocbor_encoder_init(&nc, NULL, 0);
    nanocbor_fmt_array(&nc, 3);
    nanocbor_put_tstr(&nc, COSE_CONTEXT_ENCRYPT0);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_put_bstr(&nc, key->aad, key->len_aad);
    size_t len_struct = nanocbor_encoded_len(&nc);

    /* serialize to byte stream */
    nanocbor_encoder_init(&nc, tbe, *len_tbe);
    nanocbor_fmt_bstr(&nc, len_struct);
    nanocbor_fmt_array(&nc, 3);
    nanocbor_put_tstr(&nc, COSE_CONTEXT_ENCRYPT0);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_put_bstr(&nc, key->aad, key->len_aad);
    *len_tbe = nanocbor_encoded_len(&nc);

    return COSE_ERROR_NONE;
}
#endif /* COSE_BACKEND_NRF */

/*******************************************************************************
 * @section COSE Encrypt0 (public)
 ******************************************************************************/

#ifndef COSE_BACKEND_NRF
int cose_aead_init(cose_aead_context_t * ctx,
        const uint8_t * key, cose_alg_t alg,
        uint8_t * iv, const size_t len_iv) 
{
    ctx->key.alg = alg;
    ctx->cipher = MBEDTLS_CIPHER_ID_AES;
    ctx->iv = iv;
    ctx->len_iv = len_iv;
    ctx->key.kid = NULL;
    ctx->key.len_kid = 0;
    ctx->key.aad = NULL;
    ctx->key.len_aad = 0;

    if (ctx->key.alg == cose_alg_aes_gcm_128) ctx->key.len_key = 16;
    else if (ctx->key.alg == cose_alg_aes_gcm_192) ctx->key.len_key = 24;
    else if (ctx->key.alg == cose_alg_aes_gcm_256) ctx->key.len_key = 32;
    else return COSE_ERROR_UNSUPPORTED;

    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {
        ctx->len_mac = 16;
        mbedtls_gcm_init(&ctx->ctx);
        mbedtls_gcm_setkey(&ctx->ctx, ctx->cipher, key, ctx->key.len_key * 8);
    } else return COSE_ERROR_UNSUPPORTED;

    return COSE_ERROR_NONE;
}

int cose_encrypt0_write(cose_aead_context_t *ctx,
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_enc = len_pld + ctx->len_mac;
    uint8_t enc[len_enc];

    size_t len_tbe = len_pld + ctx->key.len_aad;
    uint8_t tbe[len_tbe];

    if (_cose_encrypt0_tbe(&ctx->key,tbe, &len_tbe)) return COSE_ERROR_ENCODE;
    if (_cose_encrypt(ctx, pld, len_pld, tbe, len_tbe, enc)) 
        return COSE_ERROR_ENCRYPT;
    if (_cose_encrypt0_encode(ctx, enc, len_enc,  obj, len_obj)) 
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_encrypt0_read(cose_aead_context_t * ctx,
        const uint8_t * obj, const size_t len_obj, 
        uint8_t * pld, size_t * len_pld) 
{
    size_t len_tbe = len_obj + ctx->key.len_aad;
    uint8_t tbe[len_tbe];

    uint8_t * enc; size_t len_enc;

    if (_cose_encrypt0_tbe(&ctx->key, tbe, &len_tbe))  return COSE_ERROR_ENCODE;
    if (_cose_encrypt0_decode(ctx, obj, len_obj, 
                (const uint8_t **) &enc, &len_enc))
        return COSE_ERROR_DECODE;
    if (_cose_decrypt(ctx, enc, len_enc, tbe, len_tbe, pld, len_pld)) 
        return COSE_ERROR_DECRYPT;

    return COSE_ERROR_NONE;
}

void cose_aead_free(cose_aead_context_t * ctx) 
{
     mbedtls_gcm_free(&ctx->ctx);
}
#endif /* COSE_BACKEND_NRF */

