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

#ifndef COSE_H
#define COSE_H

#include <string.h>
#include "nanocbor/nanocbor.h"

#ifdef COSE_BACKEND_NRF
#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_error.h"
#include "nrf_crypto_ecdsa.h"
#include "nrf_crypto_hash.h"
#include "nrf_crypto_init.h"
#include "nrf_crypto_shared.h"
#else
#include <mbedtls/asn1.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif

#ifdef COSE_BACKEND_NRF
#define COSE_SHA256_TYPE COSE_PREFIX | 256
#define COSE_SHA384_TYPE COSE_PREFIX | 384
#define COSE_SHA512_TYPE COSE_PREFIX | 512
#else
#define COSE_SHA256_TYPE MBEDTLS_MD_SHA256
#define COSE_SHA384_TYPE MBEDTLS_MD_SHA384
#define COSE_SHA512_TYPE MBEDTLS_MD_SHA512
#endif

#define COSE_SHA256_LENGTH 32
#define COSE_SHA384_LENGTH 48
#define COSE_SHA512_LENGTH 64
#define COSE_P256_LENGTH 72
#define COSE_P384_LENGTH 104

#define COSE_CONTEXT_SIGN               "Signature"
#define COSE_CONTEXT_SIGN1              "Signature1"
#define COSE_CONTEXT_COUNTERSIGN        "CounterSignature"
#define COSE_CONTEXT_MAC                "MAC"
#define COSE_CONTEXT_MAC0               "MAC0"
#define COSE_CONTEXT_ENCRYPT            "Encrypt"
#define COSE_CONTEXT_ENCRYPT0           "Encrypt0"
#define COSE_CONTEXT_ENC_RECIPIENT      "Enc_Recipient"
#define COSE_CONTEXT_MAC_RECIPIENT      "Mac_Recipient"
#define COSE_CONTEXT_REC_RECIPIENT      "Rec_Recipient"

/** 
 * @brief COSE API
 * @{
 */

#define COSE_PREFIX 0xC05E0000

#define COSE_ERROR_NONE                               0x0
#define COSE_ERROR_CRYPTO               COSE_PREFIX | 0x1
#define COSE_ERROR_CBOR                 COSE_PREFIX | 0x2
#define COSE_ERROR_UNSUPPORTED          COSE_PREFIX | 0x3
#define COSE_ERROR_ENCODE               COSE_PREFIX | 0x4
#define COSE_ERROR_DECODE               COSE_PREFIX | 0x5
#define COSE_ERROR_AUTHENTICATE         COSE_PREFIX | 0x6
#define COSE_ERROR_MISMATCH             COSE_PREFIX | 0x7
#define COSE_ERROR_HASH                 COSE_PREFIX | 0x8
#define COSE_ERROR_ENCRYPT              COSE_PREFIX | 0x9
#define COSE_ERROR_DECRYPT              COSE_PREFIX | 0xa
#define COSE_ERROR_SIGN                 COSE_PREFIX | 0xb
#define COSE_ERROR_OVERFLOW             COSE_PREFIX | 0xc

/*******************************************************************************
 * @section COSE labels
 ******************************************************************************/

typedef enum {
    cose_tag_sign = 98,
    cose_tag_sign1 = 18,
    cose_tag_encrypt = 96,
    cose_tag_encrypt0 = 16,
    cose_tag_mac = 97,
    cose_tag_mac0 = 17,
} cose_tag_t;

typedef enum {
    cose_alg_aes_gcm_128 = 1,
    cose_alg_aes_gcm_192 = 2,
    cose_alg_aes_gcm_256 = 3,
    cose_alg_hmac_256_64 = 4,
    cose_alg_hmac_256_256 = 5,
    cose_alg_hmac_384_384 = 6,
    cose_alg_hmac_512_512 = 7,
    cose_alg_cbc_mac_128_64 = 14,
    cose_alg_cbc_mac_256_64 = 15,
    cose_alg_cbc_mac_128_128 = 25,
    cose_alg_cbc_mac_256_128 = 26,
    cose_alg_aes_ccm_16_64_128 = 10,
    cose_alg_aes_ccm_16_64_256 = 11,
    cose_alg_aes_ccm_64_64_128 = 12,
    cose_alg_aes_ccm_64_64_256 = 13,
    cose_alg_aes_ccm_16_128_128 = 30,
    cose_alg_aes_ccm_16_128_256 = 31,
    cose_alg_aes_ccm_64_128_128 = 32,
    cose_alg_aes_ccm_64_128_256 = 33,
    cose_alg_ecdh_es_hkdf_256 = -25,
    cose_alg_ecdh_es_hkdf_512 = -26,
    cose_alg_ecdh_ss_hkdf_256 = -27,
    cose_alg_ecdh_ss_hkdf_512 = -28,
    cose_alg_ecdh_es_a128kw = -29,
    cose_alg_ecdh_es_a192kw = -30,
    cose_alg_ecdh_es_a256kw = -31,
    cose_alg_ecdh_ss_a128kw = -32,
    cose_alg_ecdh_ss_a192kw = -33,
    cose_alg_ecdh_ss_a256kw = -34,
    cose_alg_aes_kw_128 = -3,
    cose_alg_aes_kw_192 = -4,
    cose_alg_aes_kw_256 = -5,
    cose_alg_direct = -6,
    cose_alg_direct_hkdf_hmac_sha_256 = -10,
    cose_alg_direct_hkdf_hmac_sha_512 = -11,
    cose_alg_direct_hkdf_aes_128 = -12,
    cose_alg_direct_hkdf_aes_256 = -13,
    cose_alg_ecdsa_sha_256 = -7,
    cose_alg_ecdsa_sha_384 = -35,
    cose_alg_ecdsa_sha_512 = -36,
} cose_alg_t;

typedef enum {
    cose_header_algorithm = 1,
    cose_header_critical = 2,
    cose_header_content_type = 3,
    cose_header_kid = 4,
    cose_header_iv = 5,
    cose_header_partial_iv = 6,
    cose_header_countersign = 7,
    cose_header_operation_time = 8,
    cose_header_countersign0 = 9,
    cose_header_hkdf_salt = -20,
    cose_header_kdf_u_name = -21,
    cose_header_kdf_u_nonce = -22,
    cose_header_kdf_u_other = -23,
    cose_header_kdf_v_name = -24,
    cose_header_kdf_v_nonce = -25,
    cose_header_kdf_v_other = -26,
    cose_header_ecdh_ephemeral = -1,
    cose_header_ecdh_static = -2,
    cose_header_ecdh_epk = -1,
    cose_header_ecdh_spk = -2,
    cose_header_ecdh_spk_kid = -3,
} cose_header_t;

typedef enum {
    cose_key_label_kty = 1,
    cose_key_label_kid = 2,
    cose_key_label_alg = 3,
    cose_key_label_key_ops = 4,
    cose_key_label_base_iv = 5,
} cose_key_label_t;

typedef enum {
    cose_key_op_sign = 1,
    cose_key_op_verify = 2,
    cose_key_op_encrypt = 3,
    cose_key_op_decrypt = 4,
    cose_key_op_wrap_key = 5,
    cose_key_op_unwrap_key = 6,
    cose_key_op_derive_key = 7,
    cose_key_op_derive_bits = 8,
    cose_key_op_mac_create = 9,
    cose_key_op_mac_verify = 10,
} cose_key_op_t;

typedef enum {
    cose_kty_okp = 1,
    cose_kty_ec2 = 2,
    cose_kty_symmetric = 4,
} cose_kty_t;

typedef enum {
    cose_ec_param_crv = -1,
    cose_ec_param_x = -2,
    cose_ec_param_y = -3,
    cose_ec_param_d = -4,
} cose_ec_param_t;

typedef enum {
    cose_octet_param_crv = -1,
    cose_octet_param_x = -2,
    cose_octet_param_d = -4,
} cose_octet_param_t;

typedef enum {
    cose_symmetric_param_K = -1,
} cose_symmetric_param_t;

typedef enum {
    cose_curve_p256 = 1,
    cose_curve_p384 = 2,
    cose_curve_p251 = 3,
    cose_curve_x25519 = 4,
    cose_curve_x448 = 5,
    cose_curve_ed25519 = 6,
    cose_curve_ed448 = 7,
} cose_curve_t;

typedef enum {
    cwt_claim_iss = 1,  /* Issuer */
    cwt_claim_sub = 2,  /* Subject */
    cwt_claim_aud = 3,  /* Audience */
    cwt_claim_exp = 4,  /* Expiration Time */
    cwt_claim_nbf = 5,  /* Not Before */
    cwt_claim_iat = 6,  /* Issued At */
    cwt_claim_cti = 7,  /* CWT ID */
} cwt_claim_t;

typedef enum {
    cose_mode_r = 1,    /* read */
    cose_mode_w = 2,    /* write */
} cose_mode_t;

/*******************************************************************************
 * @section Cryptographic context structs
 ******************************************************************************/

typedef struct {

    /* private */
    cose_kty_t kty;
    cose_alg_t alg;
    cose_curve_t curve;
    cose_key_op_t op;
    size_t len_key;

    /* public */
    const uint8_t * kid;
    size_t len_kid;
    const uint8_t * aad;
    size_t len_aad;

} cose_key_t;

typedef struct {

    /* TODO: dynamically allocate */
    uint8_t hash[64];
    size_t len;

#ifdef COSE_BACKEND_NRF
    int type;
    nrf_crypto_hash_context_t ctx;
#else
    mbedtls_md_type_t type;
    mbedtls_md_context_t ctx;
#endif

} cose_hash_context_t;

typedef struct {
    
    /* TODO: dynamically allocate */
    uint8_t * sig; 
    size_t len_sig;

    cose_key_t key;
    cose_mode_t mode; /* read/write */
    cose_hash_context_t hash;

#ifdef COSE_BACKEND_NRF
    union {
        nrf_crypto_ecc_private_key_t priv;
        nrf_crypto_ecc_public_key_t pub;
    } ctx;
#else
    mbedtls_pk_context ctx;
#endif

} cose_sign_context_t;

typedef struct {

    cose_key_t key;
    int cipher;
    size_t len_mac;
    uint8_t * iv;
    size_t len_iv;

#ifdef COSE_BACKEND_NRF
    nrf_crypto_aead_context_t ctx;
#else
    mbedtls_gcm_context ctx;
#endif

} cose_aead_context_t;

/*******************************************************************************
 * @section COSE API
 ******************************************************************************/

void cose_set_kid(cose_key_t * key, const uint8_t * kid, size_t len_kid);
void cose_set_aad(cose_key_t * key, const uint8_t * aad, size_t len_aad);

/**
 * @brief Initialize COSE signing context with a raw public key
 *
 * @param[in]   ctx     Pointer to uninitialized signing context
 * @param[in]   mode    0 for signature generation, 1 for verification
 * @param[in]   key     Pointer to key bytes
 * @param[in]   len_key Length of key
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_CRYPTO            Failed to parse key string 
 * @retval COSE_ERROR_UNSUPPORTED       Crypto algorithm not supported
 */
int cose_sign_raw_init(cose_sign_context_t * ctx, cose_mode_t mode, 
        const uint8_t * key, size_t len_key);

/**
 * @brief Initialize COSE signing context with a PEM-formatted key
 *
 * @param[in]   ctx     Pointer to uninitialized signing context
 * @param[in]   mode    0 for signature generation, 1 for verification
 * @param[in]   pem     PEM-formatted key string
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_CRYPTO            Failed to parse key string 
 * @retval COSE_ERROR_UNSUPPORTED       Crypto algorithm not supported
 */
int cose_sign_pem_init(cose_sign_context_t * ctx, cose_mode_t mode, 
        const char * pem);

/**
 * @brief Initialize COSE AEAD context
 *
 * @param[in]   ctx     Pointer to uninitialized encryption and MAC context
 * @param[in]   key     Pointer to raw key bytes
 * @param[in]   alg     Crypto algorithm allowed for use with this key
 * @param[in]   iv      Initialization vector
 * @param[in]   len_iv  Length of IV
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_UNSUPPORTED       Crypto algorithm not supported
 */
int cose_aead_init(cose_aead_context_t * ctx,
        const uint8_t * key, cose_alg_t alg,
        uint8_t * iv, const size_t len_iv);

/* free backend cryptographic contexts */
void cose_sign_free(cose_sign_context_t * ctx);
void cose_aead_free(cose_aead_context_t * ctx);

/**
 * @brief Encode a COSE Sign1 object
 *
 * @param[in]   ctx     Pointer to the COSE signing context
 * @param[in]   pld     Pointer to the payload to be signed 
 * @param[in]   len_pld Length of the payload
 * @param[out]  obj     Pointer to output buffer for encoded object 
 * @param[out]  len_obj Pointer to length of buffer
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_ENCODE            Failed to encode COSE object
 * @retval COSE_ERROR_HASH              Failed to hash authenticated data
 * @retval COSE_ERROR_SIGN              Failed to encrypt message diggest
 */
int cose_sign1_write(cose_sign_context_t * ctx, 
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj);

/**
 * @brief Decode a COSE Sign1 object
 *
 * @param[in]   ctx     Pointer to the COSE signing context
 * @param[in]   obj     Pointer to the encoded COSE object 
 * @param[in]   len_obj Length of encode COSE object 
 * @param[out]  pld     Pointer to payload within COSE object
 * @param[out]  len_pld Payload length
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_DECODE            Failed to decode COSE object
 * @retval COSE_ERROR_HASH              Failed to hash authenticated data
 * @retval COSE_ERROR_AUTHENTICATE      Failed to authenticate signature
 */
int cose_sign1_read(cose_sign_context_t * ctx,
        const uint8_t * obj, const size_t len_obj, 
        const uint8_t ** pld, size_t * len_pld);

/**
 * @brief Encode a COSE Encrypt0 object
 *
 * @param[in]   ctx     Pointer to the COSE encryption context
 * @param[in]   pld     Pointer to the payload to be encrypted (and MACed) 
 * @param[in]   len_pld Length of the payload
 * @param[out]  obj     Pointer to output buffer for encoded object 
 * @param[out]  len_obj Pointer to length of buffer
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_ENCODE            Failed to encode COSE object
 * @retval COSE_ERROR_ENCRYPT           Failed to encrypt (and MAC) data
 */
int cose_encrypt0_write(cose_aead_context_t *ctx,
        const uint8_t * pld, const size_t len_pld, 
        uint8_t * obj, size_t * len_obj);

/**
 * @brief Decode a COSE Encrypt0 object
 *
 * @param[in]   ctx     Pointer to the COSE AEAD context
 * @param[in]   obj     Pointer to the encoded COSE object 
 * @param[in]   len_obj Length of encode COSE object 
 * @param[out]  pld     Pointer to the output buffer for decoded payload 
 * @param[out]  len_pld Pointer to length of buffer
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_ENCODE            Failed to encode authenticated data
 * @retval COSE_ERROR_DECODE            Failed to decode COSE object 
 * @retval COSE_ERROR_DECRYPT           Failed to decrypt data
 */
int cose_encrypt0_read(cose_aead_context_t * ctx,
        const uint8_t * obj, const size_t len_obj, 
        uint8_t * pld, size_t * len_pld);

/**
 * @brief Generic cryptographic message digest API
 *
 * @param[in]   ctx     Pointer to the COSE hash context
 * @param[in]   data    Pointer to data to be hashed
 * @param[in]   len     Length of input data
 *
 * @retval COSE_ERROR_NONE              Success
 * @retval COSE_ERROR_HASH              Failed to generate message digest
 * @retval COSE_ERROR_UNSUPPORTED       Unsupported message digest algorithm
 */
int cose_hash_init(cose_hash_context_t * ctx);

int cose_hash_update(cose_hash_context_t * ctx, 
        const uint8_t * data, const size_t len);

int cose_hash_finish(cose_hash_context_t * ctx);

int cose_hash(cose_hash_context_t * ctx,
        const uint8_t * data, const size_t len);

/**
 * @}
 */

#endif /* COSE_H */
