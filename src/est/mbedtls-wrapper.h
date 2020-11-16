/*
 * Copyright (c) 2020, RISE AB.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef MBEDTLS_WRAPPER_H_
#define MBEDTLS_WRAPPER_H_

//#include <coap2/coap.h> //neded for coap_context_t
#include "est-x509.h"

#if STANDALONE_VERSION
/*
 * libcoap includes
 */
#include <coap2/net.h>
/*
 * MBED includes
 */
#include "mbedtls/pk.h"
#include <mbedtls/x509_crt.h>
#else
//#include "nrf_log_default_backends.h"
#include "nrf_crypto.h"
#endif

//TODO DAMNIT
#include "mbedtls/pk.h"
#include <mbedtls/x509_crt.h>

/*
 * Bigint defines that are still used
 */
#define WORD_LEN_BYTES 4 /**<-- Length of a word in bytes */


/**
 * MBED flags
 */
#define DFL_USE_DEV_RANDOM          0
#define DTLS_ALLOW_SELF_SIGNED_CERT 0
#define DTLS_ALLOW_EXPIRED_CERT     0


/**
 * File flags
 */
#define PEM_HEADER_AND_FOOTER_LEN	28
#define PEM_KEY_LEN               121

struct pki_info_t {
  unsigned char *fts_cert_buf; //Factory trust store [2048];
  //unsigned char *ets_cert_buf; //[PKI_ENROLLED_TS_LEN];
  unsigned char ets_cert_buf[1024];
  unsigned char *factory_cert_buf; //[512];
  unsigned char *enrolled_cert_buf; //[PKI_ENROLLED_CERT_LEN];
  x509_certificate *ca_cert;
  x509_certificate *factory_cert;
  int fts_cert_buf_len;
  int ets_cert_buf_len;
  int factory_cert_buf_len;
  int enrolled_cert_buf_len;
  uint8_t factory_key_len;
  uint8_t enrollment_key_len;
#if STANDALONE_VERSION
  mbedtls_x509_crt *mbedtls_truststore_certs;
  mbedtls_pk_context *enrollment_key_ctx;
  mbedtls_pk_context *verify_key_ctx;
#else
  mbedtls_pk_context *enrollment_key_ctx; //TODO
  unsigned char private_enrollment_key[32];
  unsigned char public_enrollment_key_x[32];
  unsigned char public_enrollment_key_y[32];
//  nrf_crypto_ecc_private_key_t * private_enrollment_key;
//  nrf_crypto_ecc_public_key_t * public_enrollment_key;
//  nrf_crypto_ecc_public_key_t * public_verify_key;
#endif

};

#ifdef STANDALONE_VERSION
struct libcoap_info_t {
	coap_context_t *ctx;
	coap_session_t *session;
};

int libcoap_save_setting(int coap_setting_type, void *setting);
int libcoap_get_setting(int coap_setting_type, void *setting);

#endif

/** Protocol level for TLS.
 *  Here, the same socket protocol level for TLS as in Linux was used.
 */
#define SOL_TLS 282
#define SOL_TLS_CREDENTIALS 283

/*
 * Compare with:
 */
//#define MBEDTLS_SSL_VERIFY_NONE                 0
//#define MBEDTLS_SSL_VERIFY_OPTIONAL             1
//#define MBEDTLS_SSL_VERIFY_REQUIRED             2

/* Valid values for TLS_DTLS_ROLE option */
#define TLS_DTLS_ROLE_CLIENT 0 /**< Client role in a DTLS session. */
#define TLS_DTLS_ROLE_SERVER 1 /**< Server role in a DTLS session. */

#define LIBCOAP_CONTEXT_TYPE 0
#define LIBCOAP_SESSION_TYPE 1


/** TLS credential types */

enum tls_credential_type {
  /** Unspecified credential. */
  TLS_CREDENTIAL_NONE,

  /**
   * One or more trusted CA certificates. Use this to authenticate the enrollment
   * server(s).
   * Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_INITIAL_TRUSTSTORE,
  /**
   * One or more trusted CA certificates. Use this to authenticate any server
   * Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_ENROLLED_TRUSTSTORE,
  /** A trusted CA certificate. Use this to authenticate remote servers.
   *  Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_CA_CERTIFICATE,

  /** A public server certificate. Use this to register your own server
   *  certificate. Should be registered together with a corresponding
   *  private key. Used with certificate-based ciphersuites.
   */
  //TLS_CREDENTIAL_SERVER_CERTIFICATE,
  TLS_CREDENTIAL_FACTORY_CERTIFICATE,

  /** A public server certificate. Use this to register your own enrolled
   *  certificate. Should be registered together with a corresponding
   *  private key. Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_ENROLLED_CERTIFICATE,

  /** Private key. Should be registered together with a corresponding
   *  factory certificate. Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_FACTORY_KEY,

  /** Private key. Should be registered together with a corresponding
   *  enrolledcertificate. Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_ENROLLMENT_KEY,

  /** Pre-shared key. Should be registered together with a corresponding
   *  PSK identity. Used with PSK-based ciphersuites.
   */
  TLS_CREDENTIAL_PSK,

  /** Pre-shared key identity. Should be registered together with a
   *  corresponding PSK. Used with PSK-based ciphersuites.
   */
  TLS_CREDENTIAL_PSK_ID
};


int est_dtls_wrapper_init(const char* ca_certs_path, int init_nrf_crypto);
int est_dtls_wrapper_free();
/*---------------------------------------------------------------------------*/
int create_ecc_signature(const unsigned char *buffer, size_t data_len, unsigned char *r_buf, const size_t r_len, unsigned char *s_buf, const size_t s_len);
int verify_ecc_signature(x509_key_context *pk_ctx, const unsigned char *buffer, size_t data_len, const unsigned char *r_buf, const size_t r_len, const unsigned char *s_buf, const size_t s_len);
int verify_own_signature(const unsigned char *buffer, size_t data_len, const unsigned char *r_buf, const size_t r_len, const unsigned char *s_buf, const size_t s_len);

int generate_enrollment_keys(x509_key_context *key_ctx);
/*---------------------------------------------------------------------------*/
int tls_credential_add(enum tls_credential_type type, void *cred, uint16_t credlen);
int tls_credential_get(enum tls_credential_type type, void *cred, uint16_t *credlen);
/*---------------------------------------------------------------------------*/
void print_hex(char const * p_msg, uint8_t const * p_data, size_t size);
/*---------------------------------------------------------------------------*/
int mbedtls_wrapper_is_locked();
void mbedtls_wrapper_release();

//void get_simple_enroll_data(uint8_t *buffer);
//int get_private_enrollment_key(unsigned char *buf_d);
int get_pem_enrollment_key(unsigned char *pem_buf);

#endif /* MBEDTLS_WRAPPER_H_ */
