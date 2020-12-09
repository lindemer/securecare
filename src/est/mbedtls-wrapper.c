/*
 * Copyright (c) 2020, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Standard includes
 */
#include "mbedtls-wrapper.h"

#include <errno.h>

/*
 * MBED includes
 */
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h> //at least for now
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"


#if STANDALONE_VERSION

#include <unistd.h> // for sleep, might delete
/*
 * MBED includes
 */
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h> //at least for now
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
/*
 * logger includes
 */
#ifdef LOG_CONF_LEVEL_WRAPPER
#define LOG_LEVEL LOG_CONF_LEVEL_WRAPPER
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif
#include "standalone_log.h"
#include "util/nrf_log_wrapper.h"
#define LOG_MODULE "wrapper"

//settings
#include "est-standalone-conf.h"

#else //Start of Embedded version

#include "nrf_crypto_shared.h"
#include "compiler_abstraction.h"

#include "nrf_log_ctrl.h"
#include "nrf_log.h"
#include "app_error.h" //APP_ERROR_CHECK"
#include "nrf_assert.h"
#include "nrf_crypto_rng.h"
#include <nrf_crypto_types.h>
#include <nrf_crypto_ecc.h>
#include "nrf_crypto.h"
#include "nrf_crypto_hash.h"

#include "project-conf.h"

#endif //End of Embedded version

/*
 * Local includes
 */
#include "est-base64.h"


/**************************************************************************************************************************/
/**************************************************************************************************************************/

#if STANDALONE_VERSION
static struct libcoap_info_t libcoap_info;
#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E  /** Copied from mbed error defs: "This is a bug in the library" */
int wrapped_x509_crt_parse_path( mbedtls_x509_crt *chain, unsigned char *chain_buffer, size_t *ts_len, const char *path);
int generate_ecc_key(mbedtls_pk_context *);

#else

static nrf_crypto_ecc_private_key_t private_enrollment_key;
static nrf_crypto_ecc_public_key_t public_enrollment_key;
static nrf_crypto_ecc_public_key_t public_verify_key;

#endif

static struct pki_info_t pki_info;

/*
 * Local/internal functions
 */
int test_set_key(mbedtls_ecp_keypair *ecp, const char *X, const char *Y, const char *d); //TODO
int get_enrollment_key(unsigned char *buf_x, unsigned char *buf_y, unsigned char *buf_d);


/**************************************************************************************************************************/
/**************************************************************************************************************************/

/*
 * PEM key structure:
 *
 *
30 77
  02 01 01
  04 20
      DC66B3415456D649429B53223DF7532B942D6B0E0842C30BCA4C0ACF91547BB2 -- private key [7--39]
  A0 0A [40-41]
    06 08 2A8648CE3D030107 [41--51]
  A1 44 [52-53]
     03 42 [54-55]
       00 04AE4CDB01F614DEFC7121285FDC7F5C6D1D42C95647F061BA0080DF67886784... -- public key [56+57+58--end]

**/
uint8_t factory_key_pem_holder[] = {
    0x30,0x77,0x02,0x01,0x01,0x04,0x20,
    0x83,0x49,0x32,0xed,0x4e,0xe1,0xaa,0x71,0x70,0x35,0x44,0x7e,0x29,0xa2,0x3e,0x90,0x81,0xd6,0x69,0xd5,0xc2,0x94,0x6b,0xda,0x5d,0x8f,0x98,0x10,0x50,0xa4,0x8d,0xcb,
    0xa0,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,
    0xa1,0x44,0x03,0x42,
      0x00,0x04,
       0xF4,0x6E,0x96,0x0B,0x89,0x70,0x43,0x1A,0x0B,0x43,0x27,0x45,0xB2,0x50,0xAD,0x89,0xE4,0x98,0x7E,0x9F,0x47,0xDA,0x34,0x7A,0x44,0xC2,0x7B,0x80,0x95,0x9F,0x82,0xD1,
       0x53,0xB3,0x7D,0xF2,0xC7,0x33,0x45,0x75,0xD6,0x9B,0x71,0x34,0x3E,0x71,0x18,0x41,0xA2,0x43,0xA3,0x98,0x8C,0x5A,0xC0,0xDA,0xC5,0x72,0xBE,0x5A,0x72,0xA7,0x7E,0x84
};
 /**************************************************************************************************************************/
 /**************************************************************************************************************************/



//#if !HAVE_RANDOM
////"28eaff.." is the public key corresponding to DEMO_NODE_KEY
//__ALIGN(4) const uint8_t ek_pub[64] =
//{
//    0x28, 0xea, 0xff, 0x3c, 0xd8, 0x16, 0x47, 0x46, 0xa3, 0x96, 0xa7, 0x79, 0x86, 0x3a, 0x30, 0x55, 0x5b, 0x87, 0x8c, 0x75, 0x07, 0x6e, 0x6f, 0xe5, 0x36, 0xea, 0x52, 0x18, 0xe2, 0x39, 0xd7, 0xc5,
//    0xc2, 0x7d, 0x1e, 0x27, 0xda, 0xe4, 0xf2, 0x7e, 0x36, 0x6b, 0x5f, 0x99, 0x5a, 0xf6, 0xa0, 0x7b, 0x1e, 0x28, 0x50, 0x96, 0x11, 0xfc, 0x6e, 0x7f, 0x90, 0xf0, 0xb5, 0xeb, 0xc5, 0xd0, 0xdb, 0xe1
//};
//
//////"0bc7ae.." is the public key corresponding to PRIVATE_ENROLLMENT_KEY
////__ALIGN(4) const uint8_t ek_pub[64] =
////{
////    0x0b, 0xc7, 0xae, 0x60, 0x68, 0x21, 0xf3, 0x0a, 0x2d, 0x17, 0x52, 0xf5, 0x12, 0x3b, 0x77, 0x66, 0x6d, 0xf9, 0xab, 0x18, 0x46, 0x15, 0xdd, 0x29, 0xf5, 0xe3, 0x02, 0xf8, 0xb3, 0xef, 0x3f, 0xb6,
////    0x7b, 0xfb, 0x2c, 0xce, 0x50, 0x2b, 0x64, 0x85, 0x9a, 0x16, 0x8f, 0x08, 0x7f, 0x8d, 0xfd, 0xe4, 0x02, 0xef, 0xdb, 0xa2, 0x1e, 0x5b, 0xc6, 0x25, 0x07, 0xab, 0x11, 0x6a, 0xfb, 0x8a, 0xb7, 0xda
////};
//
////{
////    0xd1, 0x82, 0x9f, 0x95, 0x80, 0x7b, 0xc2, 0x44, 0x7a, 0x34, 0xda, 0x47, 0x9f, 0x7e, 0x98, 0xe4, 0x89, 0xad, 0x50, 0xb2, 0x45, 0x27, 0x43, 0x0b, 0x1a, 0x43, 0x70, 0x89, 0x0b, 0x96, 0x6e, 0xf4,
////    0x84, 0x7e, 0xa7, 0x72, 0x5a, 0xbe, 0x72, 0xc5, 0xda, 0xc0, 0x5a, 0x8c, 0x98, 0xa3, 0x43, 0xa2, 0x41, 0x18, 0x71, 0x3e, 0x34, 0x71, 0x9b, 0xd6, 0x75, 0x45, 0x33, 0xc7, 0xf2, 0x7d, 0xb3, 0x53
////};
//
//__ALIGN(4) uint8_t ek_pub_copy[sizeof(ek_pub)];
////{
////  0xBC,0x86,0x73,0x8C,0xF3,0xB6,0xA5,0x6A,0x02,0x7D,0xD3,0x0E,0xB6,0x3D,0xFD,0xDB,0x9C,0x16,0x59,0x3D,0x16,0x48,0xD8,0x73,0xF9,0x4C,0x19,0x46,0x19,0x19,0xC9,0x65,
////  0x85,0x61,0x23,0x05,0x0F,0x41,0x8C,0x38,0x91,0xD4,0xD3,0xD4,0xE4,0x1B,0x87,0xAB,0x54,0x2E,0xB7,0x34,0x88,0xD5,0x25,0x95,0xE3,0xAA,0x17,0x48,0x3B,0xB6,0x51,0xC3
////};
//
////b71cdd4f6bbb0ef654b12f0ba36b096b2e464a27af4cebcd670fe7daf0580081 is the private key in DEMO_NODE_KEY
//__ALIGN(4) const uint8_t ek_priv[32] =
//{
//    0xb7,0x1c,0xdd,0x4f,0x6b,0xbb,0x0e,0xf6,0x54,0xb1,0x2f,0x0b,0xa3,0x6b,0x09,0x6b,0x2e,0x46,0x4a,0x27,0xaf,0x4c,0xeb,0xcd,0x67,0x0f,0xe7,0xda,0xf0,0x58,0x00,0x81
//};
//
//
////4d776454cd49c1827d0b4d3b89ef20b28ff2cf8c0ec8cb686e4d0067a0307d15 is the private key in PRIVATE_ENROLLMENT_KEY
////__ALIGN(4) const uint8_t ek_priv[32] =
////{
////    0x4d,0x77,0x64,0x54,0xcd,0x49,0xc1,0x82,0x7d,0x0b,0x4d,0x3b,0x89,0xef,0x20,0xb2,0x8f,0xf2,0xcf,0x8c,0x0e,0xc8,0xcb,0x68,0x6e,0x4d,0x00,0x67,0xa0,0x30,0x7d,0x15
////};
//
////{
////    0x83,0x49,0x32,0xed,0x4e,0xe1,0xaa,0x71,0x70,0x35,0x44,0x7e,0x29,0xa2,0x3e,0x90,0x81,0xd6,0x69,0xd5,0xc2,0x94,0x6b,0xda,0x5d,0x8f,0x98,0x10,0x50,0xa4,0x8d,0xcb
////};
//
//__ALIGN(4) uint8_t  ek_priv_copy[sizeof(ek_priv)];
//
//#endif //test keys for running node without RNG
#if !STANDALONE_VERSION
__ALIGN(4) uint8_t static ek_pub_copy[sizeof(demo_node_key_pub)];
__ALIGN(4) uint8_t  ek_priv_copy[sizeof(demo_node_key_priv)];
#endif

/*
 * Below is test enrollment data ...
 */

//__ALIGN(4) const uint8_t simple_enroll_data[224] =
//{
//    0x30,0x81,0xdd,0x30,0x81,0x84,0x02,0x01,0x00,0x30,0x22,0x31,0x20,0x30,0x1e,0x06,0x03,0x55,0x04,0x03,0x13,0x17,0x30,0x45,0x2d,0x30,0x39,0x2d,0x30,0x41,0x2d,0x30,0x43,0x2d,0x30,0x38,0x2d,0x30,0x37,0x2d,0x30,0x42,0x2d,0x30,0x31,0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0xf4,0x6e,0x96,0x0b,0x89,0x70,0x43,0x1a,0x0b,0x43,0x27,0x45,0xb2,0x50,0xad,0x89,0xe4,0x98,0x7e,0x9f,0x47,0xda,0x34,0x7a,0x44,0xc2,0x7b,0x80,0x95,0x9f,0x82,0xd1,0x53,0xb3,0x7d,0xf2,0xc7,0x33,0x45,0x75,0xd6,0x9b,0x71,0x34,0x3e,0x71,0x18,0x41,0xa2,0x43,0xa3,0x98,0x8c,0x5a,0xc0,0xda,0xc5,0x72,0xbe,0x5a,0x72,0xa7,0x7e,0x84,0xa0,0x00,0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x03,0x48,0x00,0x30,0x45,0x02,0x21,0x00,0xfc,0x61,0x4a,0x84,0xe3,0xac,0xc8,0xd8,0xb3,0x2f,0xb9,0x89,0xbd,0x2a,0xf6,0xd7,0xef,0xe2,0x6b,0x48,0xaa,0x02,0xa0,0x03,0xfa,0x7f,0xc4,0x0e,0xf9,0x65,0x04,0xdb,0x02,0x20,0x23,0x83,0xdd,0x41,0x93,0x1b,0x52,0xbe,0xd2,0xdb,0x8c,0x8f,0x8f,0x39,0x17,0x4d,0xc4,0x16,0xcb,0x45,0x05,0xaf,0xa8,0x43,0x35,0xab,0xfe,0x06,0xaa,0x6c,0x04,0x9a
//};

/*
 * Below is the rfc-test key -- 0xae, 0x4c, 0xdb ...
 */
//__ALIGN(4) const uint8_t ek_ca_pub[64] =
//{
//    0xae, 0x4c, 0xdb, 0x01, 0xf6, 0x14, 0xde, 0xfc, 0x71, 0x21, 0x28, 0x5f, 0xdc, 0x7f, 0x5c, 0x6d, 0x1d, 0x42, 0xc9, 0x56, 0x47, 0xf0, 0x61, 0xba, 0x00, 0x80, 0xdf, 0x67, 0x88, 0x67, 0x84, 0x5e,
//    0xe9, 0xa6, 0x9f, 0xd4, 0x89, 0x31, 0x49, 0xda, 0xe3, 0xd3, 0xb1, 0x54, 0x16, 0xd7, 0x53, 0x2c, 0x38, 0x71, 0x52, 0xb8, 0x0b, 0x0d, 0xf3, 0xe1, 0xaf, 0x40, 0x8a, 0x95, 0xd3, 0x07, 0x1e, 0x58
//};

/*
 * "As you can see in the table in Appendix A of RFC 4492 , curve secp256r1 defined by SECG is equivalent to P-256 defined by NIST."
 */


//__ALIGN(4) uint8_t sen_data[364] =
//{
//    0x30,0x82,0x01,0x68,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02,0xA0,0x82,0x01,0x59,0x30,0x82,0x01,0x55,0x02,0x01,0x01,0x31,0x00,0x30,0x0B,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01,0xA0,0x82,0x01,0x3B,0x30,0x82,0x01,0x37,0x30,0x81,0xDE,0xA0,0x03,0x02,0x01,0x02,0x02,0x03,0x01,0xF5,0x0D,0x30,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02,0x30,0x16,0x31,0x14,0x30,0x12,0x06,0x03,0x55,0x04,0x03,0x0C,0x0B,0x52,0x46,0x43,0x20,0x74,0x65,0x73,0x74,0x20,0x43,0x41,0x30,0x1E,0x17,0x0D,0x32,0x30,0x30,0x38,0x31,0x32,0x31,0x33,0x34,0x36,0x34,0x30,0x5A,0x17,0x0D,0x32,0x31,0x30,0x39,0x31,0x33,0x31,0x33,0x34,0x36,0x34,0x30,0x5A,0x30,0x22,0x31,0x20,0x30,0x1E,0x06,0x03,0x55,0x04,0x03,0x13,0x17,0x30,0x45,0x2D,0x30,0x39,0x2D,0x30,0x41,0x2D,0x30,0x43,0x2D,0x30,0x38,0x2D,0x30,0x37,0x2D,0x30,0x42,0x2D,0x30,0x31,0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0xF4,0x6E,0x96,0x0B,0x89,0x70,0x43,0x1A,0x0B,0x43,0x27,0x45,0xB2,0x50,0xAD,0x89,0xE4,0x98,0x7E,0x9F,0x47,0xDA,0x34,0x7A,0x44,0xC2,0x7B,0x80,0x95,0x9F,0x82,0xD1,0x53,0xB3,0x7D,0xF2,0xC7,0x33,0x45,0x75,0xD6,0x9B,0x71,0x34,0x3E,0x71,0x18,0x41,0xA2,0x43,0xA3,0x98,0x8C,0x5A,0xC0,0xDA,0xC5,0x72,0xBE,0x5A,0x72,0xA7,0x7E,0x84,0xA3,0x0F,0x30,0x0D,0x30,0x0B,0x06,0x03,0x55,0x1D,0x0F,0x04,0x04,0x03,0x02,0x07,0x80,0x30,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02,0x03,0x48,0x00,0x30,0x45,0x02,0x20,0x1F,0xBE,0x2C,0x89,0xDF,0xCE,0x77,0x56,0xC9,0x17,0xDC,0xDC,0x9B,0xE7,0x57,0xA4,0x1E,0xCE,0x37,0xCD,0x74,0xC3,0x2B,0xB2,0x6D,0xF3,0x95,0xBF,0x0B,0x14,0x7E,0x9F,0x02,0x21,0x00,0x97,0x1A,0x55,0xD0,0x04,0x77,0x69,0x50,0x75,0x5E,0x6D,0x14,0x25,0x39,0xCC,0x51,0xFF,0x98,0x55,0xC5,0x8E,0xF3,0xA2,0xF4,0x37,0xFD,0xDE,0xA8,0x06,0xA5,0x6D,0x05,0xA1,0x00,0x31,0x00
//};

/**************************************************************************************************************************/
/**************************************************************************************************************************/


/*
 * Initialize keys. Load ca-cert(s) and create key contexts for signing
 * and verifying during est operations
 */
int est_dtls_wrapper_init(const char* ca_certs_path, int init_nrf_crypto) {

  NRF_LOG_DEBUG("Init crypto");
  //pki_info.mbedtls_truststore_certs = malloc(sizeof(mbedtls_x509_crt));
  //mbedtls_x509_crt_init(pki_info.mbedtls_truststore_certs);
  pki_info.fts_cert_buf = malloc(TRUSTSTORE_PARSE_BUFFER_SIZE); //TODO, check NRF_CRYPTO_ALLOC(TRUSTSTORE_PARSE_BUFFER_SIZE); //
  if(!pki_info.fts_cert_buf) {
    NRF_LOG_ERROR("Alloc failed");
    return -1;
  }

  int ret = 0;

  if(ca_certs_path) {
#if STANDALONE_VERSION

    size_t ts_len;
    //ret = x509_crt_parse_file(pki_info.mbedtls_truststore_certs, pki_info.fts_cert_buf, &ts_len, ca_certs_path);
    ret = wrapped_x509_crt_parse_path(pki_info.mbedtls_truststore_certs, pki_info.fts_cert_buf, &ts_len, ca_certs_path);

    if(ret < 0) {
      NRF_LOG_ERROR("Parsing of CA certs for truststore failed: %x\n", ret);
      return ret;
    }

    ret = tls_credential_add(TLS_CREDENTIAL_INITIAL_TRUSTSTORE, pki_info.fts_cert_buf, ts_len);
#else
    NRF_LOG_ERROR("Cannot parse files, needs hardcoded strings\n");
    return -1;
#endif

  } else {
    uint8_t ca_cert[] = CA_CERT_STRING;
    int len = sizeof(ca_cert);
    memcpy(pki_info.fts_cert_buf, ca_cert, len);
    ret = tls_credential_add(TLS_CREDENTIAL_INITIAL_TRUSTSTORE, pki_info.fts_cert_buf, len); //this is ok
  }

  if(ret < 0) {
    NRF_LOG_ERROR("Storing CA certs for truststore failed\n");
    return ret;
  }

#if STANDALONE_VERSION
  pki_info.enrollment_key_ctx = malloc(sizeof(mbedtls_pk_context));
  pki_info.verify_key_ctx = malloc(sizeof(mbedtls_pk_context));

  ret = generate_ecc_key(pki_info.enrollment_key_ctx);
  ret = generate_ecc_key(pki_info.verify_key_ctx);
#else

  ret_code_t err_code;

  if(init_nrf_crypto) {
    err_code = nrf_crypto_init();
    APP_ERROR_CHECK(err_code);
    //nrf_crypto_backend_rng_context_t *voine = malloc(6400);
//    if(NULL==voine) {
//      NRF_LOG_ERROR("No mem"); return -1;
//    }
//    err_code = nrf_crypto_rng_init(NULL, NULL);
//    APP_ERROR_CHECK(err_code);
    NRF_LOG_DEBUG("nrf_crypto_init: %x", err_code);
  } else {
    NRF_LOG_DEBUG("need to do nrf_crypto_init elsewhere");
  }

//TODO, more RNG experiments

#if HAVE_RANDOM

  nrf_crypto_ecc_key_pair_generate_context_t   * m_key_pair_generate_context = NRF_CRYPTO_ALLOC(sizeof(nrf_crypto_ecc_key_pair_generate_context_t));

  if(m_key_pair_generate_context == NULL) {
    NRF_LOG_ERROR("con alloc failed");
    return -1;
  }
  nrf_crypto_ecc_private_key_t * private_enrollment_key = NRF_CRYPTO_ALLOC(sizeof(nrf_crypto_ecc_private_key_t));

  if(private_enrollment_key == NULL) {
    NRF_LOG_ERROR("priv alloc failed");
    return -1;
  }

  nrf_crypto_ecc_public_key_t * public_enrollment_key =NRF_CRYPTO_ALLOC(sizeof(nrf_crypto_ecc_public_key_t));

  if(public_enrollment_key == NULL) {
    NRF_LOG_ERROR("pub alloc failed");
    return -1;
  }

  err_code = nrf_crypto_ecc_key_pair_generate(m_key_pair_generate_context,
                                              &g_nrf_crypto_ecc_secp256r1_curve_info,
                                              private_enrollment_key,
                                              public_enrollment_key);
//                                              pki_info.private_enrollment_key,
//                                              pki_info.public_enrollment_key);
  NRF_LOG_ERROR("err_code %x", err_code);
  int p;
  for (p=0; p < 5; p++) {
    NRF_LOG_ERROR("err_code %x %d", err_code, p);
  }
#else
  //no random, load hardcoded keys
  //NRF_LOG_FLUSH();

  NRF_LOG_DEBUG("No RNG");

  //TODO: mbed testing
  pki_info.enrollment_key_ctx = malloc(sizeof(mbedtls_pk_context));
  mbedtls_pk_init( pki_info.enrollment_key_ctx );
  ret = mbedtls_pk_parse_key(pki_info.enrollment_key_ctx, (const unsigned char *)DEMO_NODE_KEY, sizeof(DEMO_NODE_KEY), NULL, 0);
  //END TODO: testing

  // Convert public key to big-endian format for use in nrf_crypto.
  nrf_crypto_internal_double_swap_endian(ek_pub_copy, demo_node_key_pub, sizeof(demo_node_key_pub) / 2); // "/2" because 2*32

  err_code =
    nrf_crypto_ecc_public_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                  &public_enrollment_key,
                                                  ek_pub_copy, //_copy,
                                                  sizeof(demo_node_key_pub));

  APP_ERROR_CHECK(err_code);

  nrf_crypto_internal_swap_endian(ek_priv_copy, demo_node_key_priv, sizeof(demo_node_key_priv));

  err_code =
    nrf_crypto_ecc_private_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                  &private_enrollment_key,
                                                  ek_priv_copy, //ek_priv_copy,
                                                  sizeof(demo_node_key_priv));

  APP_ERROR_CHECK(err_code);


#endif
#endif

  /*
   * Below is test area
   */
  //  LOG_INFO("Initialize hardcoded test key that fails\n");
  //  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
  //  const char *X = "BC86738CF3B6A56A027DD30EB63DFDDB9C16593D1648D873F94C19461919C965";
  //  const char *Y = "856123050F418C3891D4D3D4E41B87AB542EB73488D52595E3AA17483BB651C3";
  //  const char *d = "E1424BDC2019F1B31791D9D26E0A94DAC78655AD30942C0FF8E4A9FAECC6421C";
  //  ret = test_set_key(ecp, X, Y, d);
  //	if(ret < 0) {
  //		return ret;
  //	}

  //LOG_INFO("Initialize hardcoded test key that succeeds\n");

//  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
//  const char *X = "1B491D3ECDA37EB03E58F2EA4BFE83925017F920A05F8A8420F9CB9FFB8C482B";
//  const char *Y = "DFC37AC510FB4E10E588CA4166AF424771906B1A78B7F22E2B8AE2AE38533105";
//  const char *d = "7FCD8DBA6160814A471FCE6273880F709BE635DE847576105B7B99C8AF6F2449";
//  ret = test_set_key(ecp, X, Y, d);
//  if(ret < 0) {
//    return ret;
//  }

  return ret;
}

int est_dtls_wrapper_free() {
#if STANDALONE_VERSION
  mbedtls_pk_free(pki_info.enrollment_key_ctx);
  mbedtls_pk_free(pki_info.verify_key_ctx);
#else

#endif
  return 0;
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
#ifdef STANDALONE_VERSION
/*---------------------------------------------------------------------------*/
int libcoap_save_setting(int coap_setting_type, void *setting) {
  if(LIBCOAP_SESSION_TYPE == coap_setting_type) {
    libcoap_info.session = (coap_session_t *) setting;
    return 0;
  }
  if(LIBCOAP_CONTEXT_TYPE == coap_setting_type) {
    libcoap_info.ctx = (coap_context_t *) setting;
  }
  return -1;
}
/*---------------------------------------------------------------------------*/
int libcoap_get_setting(int coap_setting_type, void *setting) {
  if(LIBCOAP_SESSION_TYPE == coap_setting_type) {
    memcpy(setting, libcoap_info.session, sizeof(coap_session_t));
    return 0;
  }
  if(LIBCOAP_CONTEXT_TYPE == coap_setting_type) {
    //memcpy(setting, libcoap_info.ctx, sizeof(coap_context_t));
    setting = libcoap_info.ctx;
    return 0;
  }
  return -1;
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/*
 * Internal helper function
 */
/*---------------------------------------------------------------------------*/


int wrapped_x509_crt_parse_path( mbedtls_x509_crt *chain, unsigned char *chain_buffer, size_t *ts_len, const char *path) {
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  size_t n;
  unsigned char *buf;

  if((ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0) {
    printf("Could not load file(s)");
    return ret;
  }

  *ts_len = n - 2*PEM_HEADER_AND_FOOTER_LEN;

  memcpy(chain_buffer, buf+PEM_HEADER_AND_FOOTER_LEN, *ts_len); //*ts_len-header-footer
  ret = mbedtls_x509_crt_parse( chain, buf, n);

  return( ret );
}


#endif


/*---------------------------------------------------------------------------*/

int tls_credential_add(enum tls_credential_type type, void *cred, uint16_t credlen)
{
  int res = 0;
  switch (type) {

  case TLS_CREDENTIAL_INITIAL_TRUSTSTORE:
    NRF_LOG_DEBUG("TLS_CREDENTIAL_INITIAL_TRUSTSTORE // Warn, will mess up orig. d.buf.");
    credlen = est_base64_decode_block_inplace((char *)cred, credlen);
    pki_info.ca_cert = x509_decode_certificate((uint8_t **)&cred, (cred+credlen));
    //x509_print_certificate(pki_info.ca_cert);
    //TODO, test chain of certs
    break;

  case TLS_CREDENTIAL_ENROLLED_TRUSTSTORE:
    NRF_LOG_DEBUG("TLS_CREDENTIAL_ENROLLED_TRUSTSTORE - setting pointer only. credlen = %d\n", credlen);
    memcpy(pki_info.ets_cert_buf, (unsigned char*)cred, credlen);
    uint8_t * start = (uint8_t *)&pki_info.ets_cert_buf;
    res = x509_decode_certificate_sequence(&start, start+credlen, &pki_info.ca_cert);
//    printf("Before\n");
//    x509_print_certificate(pki_info.ca_cert);
//    printf("After\n");
    fix_cacerts_order(pki_info.ca_cert);
//    x509_print_certificate(pki_info.ca_cert);
    NRF_LOG_DEBUG("Current first ca_cert issuer %s", pki_info.ca_cert->issuer_name.value);
    break;

  case TLS_CREDENTIAL_ENROLLED_CERTIFICATE:
    NRF_LOG_DEBUG("TLS_CREDENTIAL_ENROLLED_CERTIFICATE - store pointer to byte array\n");
    pki_info.enrolled_cert_buf = (unsigned char*)cred;
    //		pki_info.enrolled_cert_buf = (unsigned char*)cred;
    //		pki_info.enrolled_cert_buf_len = credlen;
    break;


  case TLS_CREDENTIAL_CA_CERTIFICATE:
    NRF_LOG_DEBUG("SET TLS_CREDENTIAL_CA_CERTIFICATE -- ERROR, use initial truststore\n");
    res = -1; //internal_cert_to_memory(sock, cred, 1);

    break;

  case TLS_CREDENTIAL_FACTORY_CERTIFICATE:
    NRF_LOG_DEBUG("TLS_CREDENTIAL_FACTORY_CERTIFICATE // Warning, will mess up original data buffer. credlen = %d\n", credlen);
    credlen = est_base64_decode_block_inplace((char *)cred, credlen);
    pki_info.factory_cert_buf = (unsigned char*)cred;
    pki_info.factory_cert_buf_len = credlen;
    pki_info.factory_cert = x509_decode_certificate((uint8_t **)&cred, (cred+credlen));
    //x509_print_certificate(pki_info.factory_cert);
    break;

  case TLS_CREDENTIAL_FACTORY_KEY:
    NRF_LOG_DEBUG("No setter for TLS_CREDENTIAL_FACTORY_KEY. TODO\n");
    res = -1;
    break;

  case TLS_CREDENTIAL_ENROLLMENT_KEY:
    NRF_LOG_ERROR("No setter for ENROLLMENT_KEY. Use TLS_CREDENTIAL_ENROLLED_CERTIFICATE to store certificate\n");
    return -1;

  default:
    NRF_LOG_ERROR("Error, unknown or unsupported setting: %i\n", type);
    return -1;
  }


  return res;
}
/*---------------------------------------------------------------------------*/

int tls_credential_get(enum tls_credential_type type, void *cred, uint16_t *credlen)
{
  switch (type) {

  case TLS_CREDENTIAL_CA_CERTIFICATE:
    NRF_LOG_DEBUG("GET TLS_CREDENTIAL_CA_CERTIFICATE\n");
    memcpy(cred, pki_info.ca_cert, sizeof(x509_certificate)); //pki_info.ca_cert;
    *credlen = sizeof(x509_certificate);
    //x509_print_certificate(cred);
    //cred = pki_info.ca_cert; //TODO!!
    break;

  case TLS_CREDENTIAL_FACTORY_CERTIFICATE:
    NRF_LOG_ERROR("TODO\n");
    break;

  case TLS_CREDENTIAL_FACTORY_KEY:
    NRF_LOG_ERROR("TODO\n");
    break;

  case TLS_CREDENTIAL_ENROLLMENT_KEY:
    //if(pki_info.enrollment_key_ctx != NULL) {
      NRF_LOG_DEBUG("GET TLS_CREDENTIAL_ENROLLMENT_KEYS\n");
     return get_enrollment_key(((x509_key_context*)cred)->pub_x, ((x509_key_context*)cred)->pub_y, ((x509_key_context*)cred)->priv);
    break;


  default:
    NRF_LOG_ERROR("Error, unknown or unsupported setting: %i\n", type);
    return -1;
  }
  return 1;
}

/*
int generate_enrollment_keys(x509_key_context *key_ctx) {

  pki_info.enrollment_key_ctx = malloc(sizeof(mbedtls_pk_context));
  int ret = generate_ecc_key(pki_info.enrollment_key_ctx);
  if(ret < 0) {
    return ret;
  }
  uint16_t credlen;
  return tls_credential_get(TLS_CREDENTIAL_ENROLLMENT_KEY, &key_ctx, &credlen);
}
*/


#if STANDALONE_VERSION
/*---------------------------------------------------------------------------*/
/*
 * Internal, for key-gen, if desired
 */
/*---------------------------------------------------------------------------*/

#define DEV_RANDOM_THRESHOLD        32
int dev_random_entropy_poll( void *data, unsigned char *output,
    size_t len, size_t *olen )
{
  FILE *file;
  size_t ret, left = len;
  unsigned char *p = output;
  ((void) data);

  *olen = 0;

  file = fopen( "/dev/random", "rb" );
  if( file == NULL )
    return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

  while( left > 0 )
  {
    /* /dev/random can return much less than requested. If so, try again */
    ret = fread( p, 1, left, file );
    if( ret == 0 && ferror( file ) )
    {
      fclose( file );
      return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    p += ret;
    left -= ret;
    usleep(1);
  }
  fclose( file );
  *olen = len;

  return( 0 );
}

/*---------------------------------------------------------------------------*/


int generate_ecc_key(mbedtls_pk_context *target_key_ctx) {

  int ret = 1;
  int exit_code = EXIT_FAILURE;

  mbedtls_mpi Q;
  mbedtls_entropy_context entropy;
  const char *pers = "gen_key_seed";
  mbedtls_ctr_drbg_context ctr_drbg;
  /*
   * Init stuff
   */
  mbedtls_mpi_init( &Q );

  mbedtls_pk_init(target_key_ctx);
  mbedtls_ctr_drbg_init( &ctr_drbg );


  int type = MBEDTLS_PK_ECKEY;
  int ec_curve = MBEDTLS_ECP_DP_SECP256R1;
  int use_dev_random = DFL_USE_DEV_RANDOM;

  fflush( stdout );

  mbedtls_entropy_init( &entropy );

  /*
   * Probably not to be used
   */
  if(use_dev_random)
  {
    NRF_LOG_DEBUG("Key generation using /dev/random: expensive!\n");
    fflush( stdout );

    if( ( ret = mbedtls_entropy_add_source( &entropy, dev_random_entropy_poll,
        NULL, DEV_RANDOM_THRESHOLD,
        MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )  {

      NRF_LOG_ERROR("Key generation failed, mbedtls_entropy_add_source returned -0x%04x\n", (unsigned int) -ret );
      goto exit; //keep for adding clean-up
    }
  }

  if((ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
      (const unsigned char *) pers,
      strlen(pers))) != 0 ) {

    NRF_LOG_ERROR("Key generation failed, mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret );
    goto exit; //keep for adding clean-up
  }

  NRF_LOG_DEBUG("Key context generation\n");
  fflush( stdout );

  if((ret = mbedtls_pk_setup(target_key_ctx,
      mbedtls_pk_info_from_type( (mbedtls_pk_type_t) type ) ) ) != 0 ) {
    NRF_LOG_ERROR("Key generation failed for target_key_ctx, mbedtls_pk_setup returned -0x%04x", (unsigned int) -ret );
    goto exit; //keep for adding clean-up
  }

  ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) ec_curve,
      mbedtls_pk_ec(*target_key_ctx),
      mbedtls_ctr_drbg_random, &ctr_drbg );
  if(ret != 0) {
    NRF_LOG_ERROR("Key generation failed for target_key_ctx, mbedtls_ecp_gen_key returned -0x%04x", (unsigned int) -ret );
    goto exit;
  }

  exit_code = EXIT_SUCCESS;

  exit:

  if( exit_code != EXIT_SUCCESS )
  {
#ifdef MBEDTLS_ERROR_C
    char buf[256];
    memset( buf, 0, sizeof( buf ) );
    mbedtls_strerror( ret, buf, sizeof( buf ) );
    NRF_LOG_ERROR( " - %s\n", buf );
#endif
  }
  mbedtls_mpi_free( &Q );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );

  return 1;
}
#endif

/*
 * Assuming
 * key_size = 32
 */
int get_enrollment_key(unsigned char *buf_x, unsigned char *buf_y, unsigned char *buf_d) {
  size_t key_size = ECC_DEFAULT_KEY_LEN;


#if STANDALONE_VERSION
  //const int key_size = ECC_DEFAULT_KEY_LEN;
  if(NULL==pki_info.enrollment_key_ctx){
    return -1;
  }
  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
  int ret = mbedtls_mpi_write_binary(&ecp->Q.X, buf_x, key_size);
  if(ret<0) return ret;
  ret = mbedtls_mpi_write_binary(&ecp->Q.Y, buf_y, key_size);
  if(ret<0) return ret;
  return mbedtls_mpi_write_binary(&ecp->d, buf_d, key_size);
#else

  size_t pub_key_size = 2*ECC_DEFAULT_KEY_LEN;
  __ALIGN(4) static unsigned char pub_key[2*ECC_DEFAULT_KEY_LEN];
  ret_code_t err_code = nrf_crypto_ecc_public_key_to_raw(&public_enrollment_key, pub_key, &pub_key_size);
  //TODO check further: when to revert
  APP_ERROR_CHECK(err_code);
  //NRF_LOG_WARNING("k2r2: %x", ret);
  memcpy(buf_x, pub_key, ECC_DEFAULT_KEY_LEN);
  memcpy(buf_y, pub_key+ECC_DEFAULT_KEY_LEN, ECC_DEFAULT_KEY_LEN);

  err_code = nrf_crypto_ecc_private_key_to_raw(&private_enrollment_key, buf_d, &key_size); //
  APP_ERROR_CHECK(err_code);

  return 0;

#endif
}


/**
 * This is assuming the pki_info.enrollment_key_ctx is properly initialized
 */
int create_ecc_signature(const unsigned char *buffer, size_t data_len, unsigned char *r_buf, const size_t r_len,
    unsigned char *s_buf, const size_t s_len) {

#define TEST_MBED 1

#if STANDALONE_VERSION || TEST_MBED

  const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  unsigned char *md = malloc(mdinfo->size);
  //Calculate the message digest/hash256 for the data
  int  st = mbedtls_md(mdinfo, buffer, data_len, md);

  if(st < 0) {
    NRF_LOG_ERROR("Hashing error, abort\n");
    return st;
  }

  //retrieve the previously stored enrollment keys
  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);

  //Create a signature for the hash of the data
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  //printf("4\n");


  st = mbedtls_ecdsa_sign_det(&ecp->grp, &r, &s, &ecp->d, md, mdinfo->size, MBEDTLS_MD_SHA256);

#if DEBUG_MBED_WRAPPER
  printf("Input data: %u \n", (unsigned int)data_len);
  hdumps(buffer, data_len);
  printf("\n");
  printf("HASH for signing:\n");
  hdumps(md, 32);
  printf("\n");

  //int mbedtls_mpi_write_string( const mbedtls_mpi *X, int radix, char *buf, size_t buflen, size_t *olen );
  mbedtls_mpi_write_file( "X, from key:   ", &ecp->Q.X, 16, NULL );
  mbedtls_mpi_write_file( "Y, from key:   ", &ecp->Q.Y, 16, NULL );
  mbedtls_mpi_write_file( "d, from key:   ", &ecp->d, 16, NULL );
  mbedtls_mpi_write_file( "r, generated:   ", &r, 16, NULL );
  mbedtls_mpi_write_file( "s, generated:   ", &s, 16, NULL );
#endif


  mbedtls_mpi_write_binary(&r, r_buf, r_len);
  mbedtls_mpi_write_binary(&s, s_buf, s_len);
  free(md);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  if (st != 0) {
    return -1;
  }
  return 1;

#else

  nrf_crypto_hash_sha256_digest_t     m_digest;
  const size_t m_digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;

  nrf_crypto_hash_context_t   hash_context;
  ret_code_t err_code = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
  APP_ERROR_CHECK(err_code);
  size_t digest_len = m_digest_len;

  // Run the update function
  err_code = nrf_crypto_hash_update(&hash_context, buffer, data_len);
  APP_ERROR_CHECK(err_code);

  // Run the finalize when all data has been fed to the update function.
  err_code = nrf_crypto_hash_finalize(&hash_context, m_digest, &digest_len);
  APP_ERROR_CHECK(err_code);

   static nrf_crypto_ecdsa_secp256r1_signature_t m_signature;
   static size_t m_sign_size = sizeof(m_signature);

//   err_code =  nrf_crypto_ecdsa_sign_hash(sig_info_p256,
//                                              &p_private_key,
//                                              &p_hash,
//                                              &crypto_sig);

//   NRF_LOG_FLUSH();
//   print_hex("hash", m_digest, digest_len);
//   NRF_LOG_FLUSH();

   err_code =  nrf_crypto_ecdsa_sign(NULL,
                                              &private_enrollment_key,//pki_info.private_enrollment_key,
                                              m_digest,
                                              digest_len,
                                              m_signature,
                                              &m_sign_size);
   APP_ERROR_CHECK(err_code);

   //COPY R AND S. DO NOT SWAP.

   if(r_len+s_len != m_sign_size) {
     NRF_LOG_ERROR("Wrong param dim");
     return -1;
   }
   memcpy(r_buf, m_signature, r_len);
   memcpy(s_buf, m_signature+r_len, s_len);
   return 0;

#endif

}


/**
 * This is assuming the pki_info.verify_key_ctx is properly initialized
 */
int verify_ecc_signature(x509_key_context *verify_pk_ctx, const unsigned char *buffer, size_t data_len, const unsigned char *r_buf, const size_t r_len, const unsigned char *s_buf, const size_t s_len) {

#if STANDALONE_VERSION
  /*
   * Replacing the ecc part of x509_verify_ecdsa_signature
   */
  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.verify_key_ctx);
  mbedtls_mpi_read_binary(&ecp->Q.X, verify_pk_ctx->pub_x, ECC_DEFAULT_KEY_LEN);
  mbedtls_mpi_read_binary(&ecp->Q.Y, verify_pk_ctx->pub_y, ECC_DEFAULT_KEY_LEN);

  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  mbedtls_mpi_read_binary(&r, r_buf, r_len);
  mbedtls_mpi_read_binary(&s, s_buf, s_len);

  const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  unsigned char *md = malloc(mdinfo->size);
  //Hash
  mbedtls_md(mdinfo, buffer, data_len, md);

#if DEBUG_MBED_WRAPPER
  printf("Data to check: %u \n", (unsigned int)data_len);
  hdumps(buffer, data_len);
  printf("\n");
  printf("HASH of signing:\n");
  hdumps(md, 32);
  printf("\n");

  mbedtls_mpi_write_file( "X, from key:   ", &ecp->Q.X, 16, NULL );
  mbedtls_mpi_write_file( "Y, from key:   ", &ecp->Q.Y, 16, NULL );
  //mbedtls_mpi_write_file( "d, from key:   ", &ecp->d, 16, NULL );
  mbedtls_mpi_write_file( "r, to check:   ", &r, 16, NULL );
  mbedtls_mpi_write_file( "s, to check:   ", &s, 16, NULL );
  printf("r-len & s-len: %u %u\n", (unsigned int)r_len, (unsigned int)s_len);
#endif

  //Verify the signature
  int st = mbedtls_ecdsa_verify(&ecp->grp, md, mdinfo->size, &ecp->Q, &r, &s);

  //Cleanup
  free(md);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  if (st != 0) {
    printf("st: %x\n", st);
    return -1;
  }

  return 1;
#else

  ret_code_t err_code;

  /**
   * Init verify key
   */

  memcpy(ek_pub_copy, verify_pk_ctx->pub_x, ECC_DEFAULT_KEY_LEN);
  memcpy(ek_pub_copy+ECC_DEFAULT_KEY_LEN, verify_pk_ctx->pub_y, ECC_DEFAULT_KEY_LEN);

  //DO NOT SWAP when the verify_key is created from the CA-key

  err_code =
    nrf_crypto_ecc_public_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                  &public_verify_key,
                                                  ek_pub_copy, //_copy,
                                                  sizeof(demo_node_key_pub));
//
  APP_ERROR_CHECK(err_code);

  /**
   * Recalculate hash
   */

  nrf_crypto_hash_sha256_digest_t     m_digest;
  const size_t m_digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;

  nrf_crypto_hash_context_t   hash_context;
  err_code = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
  APP_ERROR_CHECK(err_code);
  size_t digest_len = m_digest_len;

  // Run the update function
  err_code = nrf_crypto_hash_update(&hash_context, buffer, data_len);
  APP_ERROR_CHECK(err_code);

  // Run the finalize when all data has been fed to the update function.
  err_code = nrf_crypto_hash_finalize(&hash_context, m_digest, &digest_len);
  APP_ERROR_CHECK(err_code);
  NRF_LOG_INFO("h2-err %x", err_code);

  /**
   * Init signature to check
   */

   static nrf_crypto_ecdsa_secp256r1_signature_t m_signature;
   static size_t m_signature_size = sizeof(m_signature);
   memcpy(m_signature, r_buf, r_len);
   memcpy(m_signature+s_len, s_buf, s_len);
   NRF_LOG_DEBUG("m_signature_size %lu", m_signature_size);

   /**
    * Verify signature
    */

   err_code = nrf_crypto_ecdsa_verify(NULL, &public_verify_key, m_digest, digest_len, m_signature, m_signature_size);

   APP_ERROR_CHECK(err_code);

  if(err_code != NRF_SUCCESS )
  {
    NRF_LOG_ERROR("verification failed %x .\r\n",err_code);
    return -err_code;
  }

   NRF_LOG_INFO("Signature verified \r\n");

  return 0;

#endif

}

#if !STANDALONE_VERSION
int verify_own_signature(const unsigned char *buffer, size_t data_len, const unsigned char *r_buf, const size_t r_len, const unsigned char *s_buf, const size_t s_len) {

  ret_code_t err_code;

  /**
   * Recalculate hash
   */

  nrf_crypto_hash_sha256_digest_t     m_digest;
  const size_t m_digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;

  nrf_crypto_hash_context_t   hash_context;
  err_code = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
  APP_ERROR_CHECK(err_code);
  size_t digest_len = m_digest_len;

  // Run the update function
  err_code = nrf_crypto_hash_update(&hash_context, buffer, data_len);
  APP_ERROR_CHECK(err_code);

  // Run the finalize when all data has been fed to the update function.
  err_code = nrf_crypto_hash_finalize(&hash_context, m_digest, &digest_len);
  APP_ERROR_CHECK(err_code);

  /**
   * Init signature to check
   */

   static nrf_crypto_ecdsa_secp256r1_signature_t m_signature;
   static size_t m_signature_size = sizeof(m_signature);
   memcpy(m_signature, r_buf, r_len);
   memcpy(m_signature+s_len, s_buf, s_len);

   /**
    * Verify signature
    */

   err_code = nrf_crypto_ecdsa_verify(NULL, &public_enrollment_key, m_digest, digest_len, m_signature, m_signature_size);

   APP_ERROR_CHECK(err_code);

  if(err_code !=NRF_SUCCESS )
  {
    NRF_LOG_ERROR("verification failed %x .\r\n",err_code);
    return -err_code;
  }

   NRF_LOG_INFO("Signature verified \r\n");

  return 0;

}
#endif
/**************************************************************************************************************************/
/**************************************************************************************************************************/

#define PEM_PRIVATE_KEY_OFFSET 7
#define PEM_PUBLIC_KEY_OFFSET 57

int get_pem_enrollment_key(unsigned char *pem_buf) {

  size_t key_size = ECC_DEFAULT_KEY_LEN;


#if STANDALONE_VERSION
  //const int key_size = ECC_DEFAULT_KEY_LEN;
  if(NULL==pki_info.enrollment_key_ctx){
    return -1;
  }
  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
  return mbedtls_mpi_write_binary(&ecp->d, pem_buf, key_size);
#else

  size_t pub_key_size = 2*ECC_DEFAULT_KEY_LEN;
  memcpy(pem_buf, factory_key_pem_holder, sizeof(factory_key_pem_holder));

  ret_code_t err_code = nrf_crypto_ecc_private_key_to_raw(&private_enrollment_key, pem_buf+PEM_PRIVATE_KEY_OFFSET, &key_size); //
  APP_ERROR_CHECK(err_code);
  err_code = nrf_crypto_ecc_public_key_to_raw(&public_enrollment_key, pem_buf+PEM_PUBLIC_KEY_OFFSET, &pub_key_size);
  //TODO double check swap_endian * 2
  APP_ERROR_CHECK(err_code);

  if(err_code != NRF_SUCCESS) {
    return -err_code;
  }
#endif
  return 0;
}

/**************************************************************************************************************************/
/**************************************************************************************************************************/

/*
 * Leftover test code
 */
//	LOG_INFO("Initialize hardcoded test key\n");
//	mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
//	const char *X = "BC86738CF3B6A56A027DD30EB63DFDDB9C16593D1648D873F94C19461919C965";
//	const char *Y = "856123050F418C3891D4D3D4E41B87AB542EB73488D52595E3AA17483BB651C3";
//	const char *d = "E1424BDC2019F1B31791D9D26E0A94DAC78655AD30942C0FF8E4A9FAECC6421C";
//	test_set_key(ecp, X, Y, d);

/*
 * Internal util
 */
int test_set_key(mbedtls_ecp_keypair *ecp, const char *X, const char *Y, const char *d) {

  int ret = 0;

  ret = mbedtls_mpi_read_string(&ecp->Q.X, 16, X);
  if(ret < 0) return ret;
  ret = mbedtls_mpi_read_string(&ecp->Q.Y, 16, Y);
  if(ret < 0) return ret;
  ret = mbedtls_mpi_read_string(&ecp->d, 16, d);
  if(ret < 0) return ret;
  //ecp->d = NULL;
#if DEBUG_MBED_WRAPPER
  mbedtls_mpi_write_file( "X_Q, loaded:   ", &ecp->Q.X, 16, NULL );
  mbedtls_mpi_write_file( "Y_Q, loaded:   ", &ecp->Q.Y, 16, NULL );
#endif

  return 0;
}

/**************************************************************************************************************************/


///*
// * Internal util
// */
//int test_set_key(mbedtls_ecp_keypair *ecp, const char *X, const char *Y, const char *d) {
//
//  int ret = 0;
//
//  ret = mbedtls_mpi_read_string(&ecp->Q.X, 16, X);
//  if(ret < 0) return ret;
//  ret = mbedtls_mpi_read_string(&ecp->Q.Y, 16, Y);
//  if(ret < 0) return ret;
//  ret = mbedtls_mpi_read_string(&ecp->d, 16, d);
//  if(ret < 0) return ret;
//  //ecp->d = NULL;
//#if DEBUG_MBED_WRAPPER
//  mbedtls_mpi_write_file( "X_Q, loaded:   ", &ecp->Q.X, 16, NULL );
//  mbedtls_mpi_write_file( "Y_Q, loaded:   ", &ecp->Q.Y, 16, NULL );
//#endif
//
//  return 0;
//}

#if !STANDALONE_VERSION

/**************************************************************************************************************************/
static void print_array(uint8_t const * p_string, size_t size)
{
    size_t i;
    NRF_LOG_RAW_INFO("    ");
    for(i = 0; i < size; i++)
    {
        NRF_LOG_RAW_INFO("%02x", p_string[i]);
    }
}

void print_hex(char const * p_msg, uint8_t const * p_data, size_t size)
{
    NRF_LOG_INFO(p_msg);
    print_array(p_data, size);
    NRF_LOG_RAW_INFO("\r\n");
}
/**************************************************************************************************************************/

#endif

