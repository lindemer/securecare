/**
 * Copyright (c) 2020, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **/

#include "cose.h"

/***************************************************************************************************
 * @section Common to all COSE objects
 **************************************************************************************************/

#define HASH_TSTR(md_ctx, nc, buf, len_buf, str)                                                   \
    nanocbor_encoder_init(&nc, buf, len_buf);                                                      \
    nanocbor_fmt_tstr(&nc, strlen((const char *) str));                                            \
    mbedtls_md_update(&md_ctx, buf, nanocbor_encoded_len(&nc));                                    \
    mbedtls_md_update(&md_ctx, str, strlen((const char *) str));

#define HASH_BSTR(md_ctx, nc, buf, len_buf, bstr, len_bstr)                                        \
    nanocbor_encoder_init(&nc, buf, len_buf);                                                      \
    nanocbor_fmt_bstr(&nc, len_bstr);                                                              \
    mbedtls_md_update(&md_ctx, buf, nanocbor_encoded_len(&nc));                                    \
    mbedtls_md_update(&md_ctx, bstr, len_bstr);

void cose_set_kid(cose_key_t * key, const uint8_t * kid, size_t len_kid)
{
    key->kid = kid;
    key->len_kid = len_kid;
}

void cose_set_aad(cose_key_t * key, const uint8_t * aad, size_t len_aad)
{
    key->aad = aad;
    key->len_aad = len_aad;
}

int cose_encode_prot(cose_key_t * key, nanocbor_encoder_t * nc)
{
    nanocbor_fmt_map(nc, 1);
    nanocbor_fmt_int(nc, cose_header_algorithm);
    nanocbor_fmt_int(nc, key->alg);
    return nanocbor_encoded_len(nc);
}

/***************************************************************************************************
 * @section COSE Sign1
 **************************************************************************************************/

int cose_sign_init(
        cose_sign_context_t * ctx, 
        cose_mode_t mode, 
        const char * pem) 
{
    mbedtls_pk_init(&ctx->pk);

    if (mode == cose_mode_r) {
        ctx->key.op = cose_key_op_verify;
        if (mbedtls_pk_parse_public_key(&ctx->pk, 
                    (const unsigned char *) pem, strlen(pem) + 1)) 
            return COSE_ERROR_MBEDTLS;

    } else if (mode == cose_mode_w) {
        ctx->key.op = cose_key_op_sign;
        if (mbedtls_pk_parse_key(&ctx->pk, 
                    (const unsigned char *) pem, strlen(pem) + 1, NULL, 0)) 
            return COSE_ERROR_MBEDTLS;

    } else return COSE_ERROR_UNSUPPORTED;

    ctx->key.kty = cose_kty_ec2;
    mbedtls_ecp_group_id grp_id = mbedtls_pk_ec(ctx->pk)->grp.id;

    if (grp_id == MBEDTLS_ECP_DP_SECP256R1) {
        ctx->len_hash = 32;
        ctx->key.crv = cose_curve_p256;
        ctx->key.alg = cose_alg_ecdsa_sha_256;
        ctx->md_alg = MBEDTLS_MD_SHA256;
        ctx->len_sig = 72;
    } else if (grp_id == MBEDTLS_ECP_DP_SECP384R1) {
        ctx->len_hash = 48;
        ctx->key.crv = cose_curve_p384;
        ctx->key.alg = cose_alg_ecdsa_sha_384;
        ctx->md_alg = MBEDTLS_MD_SHA384;
        ctx->len_sig = 104;
    } else return COSE_ERROR_UNSUPPORTED;

    ctx->key.kid = NULL;
    ctx->key.len_kid = 0;
    ctx->key.aad = NULL;
    ctx->key.len_aad = 0;

    return COSE_ERROR_NONE;
}

int cose_sign1_hash(
        cose_sign_context_t * ctx, const uint8_t *pld, const size_t len_pld,
        uint8_t * hash)
{
    mbedtls_md_context_t md_ctx;
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(ctx->md_alg), 0);
    mbedtls_md_starts(&md_ctx);
    nanocbor_encoder_t nc;

    /* serialize body_protected */
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(&ctx->key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(&ctx->key, &nc);

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
    mbedtls_md_update(&md_ctx, buf, nanocbor_encoded_len(&nc));

    HASH_TSTR(md_ctx, nc, buf, len_buf, (const unsigned char *) COSE_CONTEXT_SIGN1)
    HASH_BSTR(md_ctx, nc, buf, len_buf, prot, len_prot)
    HASH_BSTR(md_ctx, nc, buf, len_buf, ctx->key.aad, ctx->key.len_aad)
    HASH_BSTR(md_ctx, nc, buf, len_buf, pld, len_pld)

    if (mbedtls_md_finish(&md_ctx, hash)) return COSE_ERROR_HASH;
    return COSE_ERROR_NONE;
}

int cose_sign1_encode(
        cose_key_t * key,
        const uint8_t * pld, const size_t len_pld, 
        const uint8_t * sig, const size_t len_sig,
        uint8_t * obj, size_t * len_obj) 
{
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(key, &nc);

    nanocbor_encoder_init(&nc, obj, *len_obj);
    nanocbor_fmt_tag(&nc, cose_tag_sign1);
    nanocbor_fmt_array(&nc, 4);
    nanocbor_put_bstr(&nc, prot, len_prot);
    nanocbor_fmt_map(&nc, 0);
    nanocbor_put_bstr(&nc, pld, len_pld);
    nanocbor_put_bstr(&nc, sig, len_sig);
    *len_obj = nanocbor_encoded_len(&nc);

    return COSE_ERROR_NONE;
}

int cose_sign1_decode(
        cose_sign_context_t * ctx,
        const uint8_t * obj, const size_t len_obj,
        const uint8_t ** pld, size_t * len_pld,
        const uint8_t ** sig, size_t * len_sig, 
        uint8_t * hash)
{
    nanocbor_value_t nc, arr;
    nanocbor_decoder_init(&nc, obj, len_obj);
    nanocbor_skip(&nc);
    if (nanocbor_enter_array(&nc, &arr) < 0) return COSE_ERROR_DECODE;
    nanocbor_skip(&arr);
    nanocbor_skip(&arr);
    nanocbor_get_bstr(&arr, pld, len_pld); 

    cose_sign1_hash(ctx, *pld, *len_pld, hash);
    nanocbor_get_bstr(&arr, sig, len_sig); 

    return COSE_ERROR_NONE;
}

int cose_sign1_write(cose_sign_context_t * ctx, 
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj) 
{
    uint8_t hash[ctx->len_hash];
    uint8_t sig[ctx->len_sig];
    
    cose_sign1_hash(ctx, pld, len_pld, hash);

    //if (mbedtls_ecdsa_write_signature(ctx->pk.pk_ctx, ctx->md_alg, hash, ctx->len_hash, 
    //            sig, &ctx->len_sig, NULL, NULL)) 
    //    return COSE_ERROR_SIGN;
    //
    return mbedtls_ecdsa_write_signature(ctx->pk.pk_ctx, ctx->md_alg, hash, ctx->len_hash, 
                sig, &ctx->len_sig, NULL, NULL);

    if (cose_sign1_encode(&ctx->key, pld, len_pld, sig, ctx->len_sig, obj, len_obj))
        return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_sign1_read(cose_sign_context_t * ctx, 
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t ** pld, size_t * len_pld) 
{
    uint8_t hash[ctx->len_hash];
    uint8_t * sig;
    size_t len_sig;

    if (cose_sign1_decode(ctx, obj, len_obj, pld, len_pld, (const uint8_t **) &sig, &len_sig, hash))
        return COSE_ERROR_DECODE;
    if (mbedtls_pk_verify(&ctx->pk, ctx->md_alg, hash, 0, sig, len_sig))
        return COSE_ERROR_AUTHENTICATE;

    return COSE_ERROR_NONE;
}

void cose_sign_free(cose_sign_context_t * ctx) 
{
    mbedtls_pk_free(&ctx->pk);
}

/***************************************************************************************************
 * @section COSE Encrypt0
 **************************************************************************************************/

int cose_crypt_init(cose_crypt_context_t * ctx,
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
        mbedtls_gcm_init(&ctx->gcm);
        mbedtls_gcm_setkey(&ctx->gcm, ctx->cipher, key, ctx->key.len_key * 8);
    } else return COSE_ERROR_UNSUPPORTED;

    return COSE_ERROR_NONE;
}

int cose_do_encrypt(
        cose_crypt_context_t * ctx,
        const uint8_t * pld, const size_t len_pld,
        const uint8_t * tbe, const size_t len_tbe,
        uint8_t * enc) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {

        if (mbedtls_gcm_crypt_and_tag(&ctx->gcm, MBEDTLS_GCM_ENCRYPT, len_pld, ctx->iv, ctx->len_iv,
                    tbe, len_tbe, pld, enc, ctx->len_mac, enc + len_pld))
            return COSE_ERROR_ENCRYPT;

    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int cose_do_decrypt(
        cose_crypt_context_t * ctx,
        const uint8_t * enc, const size_t len_enc,
        const uint8_t * tbe, const size_t len_tbe,
        uint8_t * pld, size_t * len_pld) 
{
    if (ctx->key.alg == cose_alg_aes_gcm_128 || 
        ctx->key.alg == cose_alg_aes_gcm_192 ||
        ctx->key.alg == cose_alg_aes_gcm_256) {

        *len_pld = len_enc - ctx->len_mac;
        if (mbedtls_gcm_auth_decrypt(&ctx->gcm, *len_pld, ctx->iv, ctx->len_iv, tbe, len_tbe, 
                    enc + *len_pld, ctx->len_mac, enc, pld))
            return COSE_ERROR_DECRYPT;
            
    } else return COSE_ERROR_UNSUPPORTED;
    return COSE_ERROR_NONE;
}

int cose_tbe0(
        cose_key_t * key,
        uint8_t * tbe, size_t * len_tbe)
{
    /* serialize protected */
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(key, &nc);
   
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

int cose_encrypt0_encode(
        cose_crypt_context_t * ctx,
        const uint8_t * enc, const size_t len_enc, 
        uint8_t * obj, size_t * len_obj) 
{
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, NULL, 0);
    size_t len_prot = cose_encode_prot(&ctx->key, &nc);
    uint8_t prot[len_prot];
    nanocbor_encoder_init(&nc, prot, len_prot);
    cose_encode_prot(&ctx->key, &nc);

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

int cose_encrypt0_decode(
        cose_crypt_context_t * ctx,
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
            if (nanocbor_get_bstr(&map, (const uint8_t **) &ctx->iv, &ctx->len_iv) < 0)
                return COSE_ERROR_DECODE;
            else break;
        }
        nanocbor_skip(&map); 
    }

    nanocbor_skip(&arr); 
    if (nanocbor_get_bstr(&arr, enc, len_enc) < 0) return COSE_ERROR_DECODE;

    return COSE_ERROR_NONE;
}

int cose_encrypt0_write(cose_crypt_context_t *ctx,
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj) 
{
    size_t len_enc = len_pld + ctx->len_mac;
    uint8_t enc[len_enc];

    size_t len_tbe = len_pld + ctx->key.len_aad;
    uint8_t tbe[len_tbe];

    if (cose_tbe0(&ctx->key,tbe, &len_tbe)) return COSE_ERROR_ENCODE;
    if (cose_do_encrypt(ctx, pld, len_pld, tbe, len_tbe, enc)) return COSE_ERROR_ENCRYPT;
    if (cose_encrypt0_encode(ctx, enc, len_enc,  obj, len_obj)) return COSE_ERROR_ENCODE;

    return COSE_ERROR_NONE;
}

int cose_encrypt0_read(cose_crypt_context_t * ctx,
        const uint8_t * obj, const size_t len_obj, 
        uint8_t * pld, size_t * len_pld) 
{
    size_t len_tbe = len_obj + ctx->key.len_aad;
    uint8_t tbe[len_tbe];

    uint8_t * enc; size_t len_enc;

    if (cose_tbe0(&ctx->key, tbe, &len_tbe))  return COSE_ERROR_ENCODE;
    if (cose_encrypt0_decode(ctx, obj, len_obj, (const uint8_t **) &enc, &len_enc))
        return COSE_ERROR_DECODE;
    if (cose_do_decrypt(ctx, enc, len_enc, tbe, len_tbe, pld, len_pld)) return COSE_ERROR_DECRYPT;

    return COSE_ERROR_NONE;
}

void cose_crypt_free(cose_crypt_context_t * ctx) 
{
     mbedtls_gcm_free(&ctx->gcm);
}

