/*
 * Copyright (c) 2015, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *          Functions for main est operations

 * \author
 *         Rúnar Már Magnússon <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "est.h"
#include "est-cms.h"
#include "est-pkcs10.h"
#include "est-x509.h"
#include "est-client.h" //settings
#include "est-asn1.h"
//#include "est-standalone-conf.h" //settings

#if TEST_ENROLL_SUBJECT
extern const char client_mac_id[];
#else
extern const uint8_t client_mac_id[];
#endif


//#include "os/net/security/other-ecc/other-ecc.h"


#include "nanocbor/nanocbor.h"

#include "xiot.h"

#include "crypto-wrapper.h"

#if STANDALONE_VERSION
#include "util/nrf_log_wrapper.h"
#define LOG_MODULE "est"
#ifdef LOG_CONF_LEVEL_EST
#define LOG_LEVEL LOG_CONF_LEVEL_EST
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif
#include "standalone_log.h"
#else //== not standalone version
//#define NRF_LOG_LEVEL 5
//#define NRF_LOG_MODULE_NAME est
#include "nrf_log_ctrl.h"
#include "nrf_log.h"
//NRF_LOG_MODULE_REGISTER();
//#include "nrf_log_wrapper.h"
#endif

//static int (*setsockopt)(int level, int optname,
//        void *optval, uint16_t optlen);
//
//static int (*getsockopt)(int level, int optname,
//         void *optval, uint16_t *optlen);


//#if !EST_WITH_COFFEE
//est_session_data *session_data;
//
///* TODO: (CA Rollover) Implement function to perform CA rollover when the CA
// * certificate is changed */
//
///* TODO: (Server-generated key request) Implement support for the server-generated
// * cryptograhic keys (OPTIONAL) */
//
///*----------------------------------------------------------------------------*/
//void
//est_session_init(est_session_data *session)
//{
//  memset(session, 0, sizeof(est_session_data));
//  session_data = session;
//}
//#endif
/*----------------------------------------------------------------------------*/

//void est_set_socket_callbacks(int (*setsocko)(int level, int optname,
//        void *optval, uint16_t optlen),
//    int (*getsocko)(int level, int optname,
//         void *optval, uint16_t *optlen)) {
//
//  setsockopt = setsocko;
//  getsockopt = getsocko;
//
//}
/*----------------------------------------------------------------------------*/
#if EST_WITH_COFFEE
static int
est_cert_to_coffee(x509_certificate *cert_in, uint8_t is_ca_cert)
{

  /* Verify the provided certificate pointer */
  if(cert_in == NULL) {
    NRF_LOG_ERROR("EST ERROR - est_cert_to_coffee: NULL pointer cert_in\n");
    return -1;
  }

  int res = 0;

  if(is_ca_cert) {
    res = x509_write_certificate_to_file(cert_in, EXPLICIT_TA);

    if(res < 0) {
      NRF_LOG_ERROR("EST ERROR - est_cert_to_coffee: Could not write Explicit TA to file\n");
      return res;
    }

    if(cert_in->next != NULL) {
      res = x509_write_certificate_to_file(cert_in->next, EXPLICIT_PATH);

      if(res < 0) {
        NRF_LOG_ERROR("EST ERROR - est_cert_to_coffee: Could not write Explicit PATH to file\n");
        return res;
      }
    }
  } else {
    res = x509_write_certificate_to_file(cert_in, MY_CERTIFICATE);

    if(res < 0) {
      NRF_LOG_ERROR("EST ERROR - est_cert_to_coffee: Could not write MY Certificate to file\n");
      return res;
    }
  }

  x509_memb_remove_certificates(cert_in);
  return 0;
}
#endif //was further below

/*----------------------------------------------------------------------------*/
static int
est_check_cacerts_order(cms_signed_data *cms)
{
  /* Check if the self signed CA is the head, otherwise swap the order */
  if(x509_cert_is_self_signed(cms->head)) {
    NRF_LOG_DEBUG("Found a not self signed cert, swap certificate order!\n");
    x509_certificate *tmp_cert = cms->head->next;
    cms->head->next = NULL;
    //int i = 0;
    while(tmp_cert != NULL) {
      //NRF_LOG_DEBUG("%d\n", i++);
      x509_certificate *next_cert = tmp_cert->next;
      tmp_cert->next = cms->head;
      cms->head = tmp_cert;
      tmp_cert = next_cert;
    }
    if(x509_verify_issuer(&cms->head->issuer_name, &cms->head->subject_name) < 0) {
      return -1;
    }
  }
  return 0;
}
/*----------------------------------------------------------------------------*/

static int
est_check_enroll_cert_subject(x509_certificate *cert_in)
{
  int res;
  uint8_t value[X509_EUI64_SUBJECT_SIZE];
  asn1_tlv eui64_subject;

  /* Get the EUI64 subject and verify that is the same in the certificate */
  res = x509_set_eui64_subject(&eui64_subject, value, X509_EUI64_SUBJECT_SIZE); //X509_EUI64_SUBJECT_SIZE == 34 = 23 + 2 + 3 + 2 + 2 + 2
  if(res < 0) {
    NRF_LOG_ERROR("EST ERROR - est_check_enroll_cert_subject: Could not set eui64 subject\n");
    return res;
  }
  res = x509_verify_subject(&eui64_subject, &cert_in->subject_name);
  if(res < 0) {
    NRF_LOG_ERROR("EST ERROR - est_check_enroll_cert_subject: Subject in certificate not the eui64 subject\n");
    return res;
  }
  return 0;
}
/*----------------------------------------------------------------------------*/
static int
est_generate_session_keys(x509_key_context *key_ctx)
{
  /* Check if session already has generated keys*/
  int has_keys = 0;

  uint16_t optlen;
  has_keys = tls_credential_get(TLS_CREDENTIAL_ENROLLMENT_KEY, key_ctx, &optlen); //getsockopt(SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_CA_CERTIFICATE, ptr_cert, &optlen);

  if(0 < has_keys) {

    NRF_LOG_DEBUG("est_gsk - SESSION HAS NO KEYS, GEN NEW\n");
    //TODO - test
    has_keys = -1; //generate_enrollment_keys(key_ctx);
    if(0 < has_keys) {
      NRF_LOG_ERROR("est_gsk - key generation failed!\n");
      return -1;
    }

  } else {

    NRF_LOG_DEBUG("est_gsk - HAS KEYS\n");
  }

    /*
     * The key context we get from settings will only contain raw key values,
     * hence we need to fill the rest here
     * */
    key_ctx->sign = ECDSA_WITH_SHA256;
    key_ctx->curve = SECP256R1_CURVE;
    key_ctx->pk_alg = ECC_PUBLIC_KEY;

  return 0;
}
/*----------------------------------------------------------------------------*/
int
est_process_cacerts_response(uint8_t *buffer, uint16_t buf_len, unsigned char *path, uint8_t *result_buffer, int *result_len)
{
  int res;
  cms_signed_data sdata;
  /* CMS decode the response */
  cms_init(&sdata);
  res = cms_decode_content_info(buffer, buf_len, result_buffer, result_len, &sdata);
  if(res < 0) {
    NRF_LOG_ERROR("est pcr: Could not decode cms\n");
    return res;
  }

  /* Check if the order of certificates is correct */
  res = est_check_cacerts_order(&sdata);
  if(res < 0) {
    NRF_LOG_ERROR("est pcr: Set cert ord err\n");
    return res;
  }

  /* TODO: (Time Syncronization) Get the current network time and use
     it in x509_verify_certificate_path to verify the validity of the certificates */

  NRF_LOG_DEBUG("CA cert p.val");
#if PLATFORM_HAS_TIME==1
  //was: res = x509_verify_certificate_path(ptr_cert->next, ptr_cert, x509_get_ctime());
  res = x509_verify_certificate_path(sdata.head->next, sdata.head, x509_get_ctime());
#else
  NRF_LOG_WARNING("no time\n");
  res = x509_verify_certificate_path(sdata.head->next, sdata.head, NULL);
  //NRF_LOG_WARNING("FAKE");
#endif

  if(res < 0) {
    NRF_LOG_ERROR("COULD NOT VERIFY CACERTS PATH\n");
    return res;
  } else {
    NRF_LOG_DEBUG("cpv\n");
  }

  /* Write CA certificates to session buffer */
  if (NULL != path) {
    NRF_LOG_DEBUG("Should store to file system");
    res = 0; //est_cert_to_coffee(sdata.head, EST_CERT_IS_CA);
    if(res < 0) {
      NRF_LOG_ERROR("EST ERROR - est_process_cacerts_response: Could not write to coffee file system\n");
      return res;
    }
  else {
    NRF_LOG_DEBUG("cp 2 cb\n");
    memcpy(result_buffer, sdata.head, sdata.head->tbs_cert_len+sdata.head->sign_len);
  }
  //TODO: should we replace existing CA, or create another one

//  res = cng_setsockopt(fd, SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_CA_CERTIFICATE, sdata.head, sdata.head->tbs_cert_len+sdata.head->sign_len);
//  if(res < 0) {
//    NRF_LOG_ERROR("est_process_cacerts_response: Could not write TLS_CREDENTIAL_CA_CERTIFICATE to buffer\n");
//    return res;
//  }
  }
  memset(buffer, 0, buf_len);
  return 0;
}
/*----------------------------------------------------------------------------*/
#if USE_CBOR_ENCODING
int
cbor_decompress_cert(uint8_t *buffer, uint16_t buf_len, uint8_t *decompressed_buffer)
{
  /*
   * Definition: https://tools.ietf.org/html/draft-mattsson-cose-cbor-cert-compress-01
   */
//    certificate = (
//       type : int,
//       serialNumber : bytes,
//       issuer : { + int => bytes } / text,
//       validity_notBefore: uint,
//       validity_notAfter: uint,
//       subject : text / bytes
//       subjectPublicKey : bytes
//       extensions : [ *4 int, ? text / bytes ] / int,
//       signatureValue : bytes,
//       ? ( signatureAlgorithm : int,
//           subjectPublicKeyInfo_algorithm : int )
//       )
  xiot_cert_t decoded_cbor_cert;

  int ret, i;
  nanocbor_value_t decoder;
  nanocbor_decoder_init(&decoder, buffer, buf_len);

  nanocbor_value_t arr; /* Array value instance */

  if (nanocbor_enter_array(&decoder, &arr) < 0) {
    NRF_LOG_ERROR("Decode error, not a valid cbor array\n");
  }
  const uint8_t *serial_bytes; //TODO alloc?
  size_t value_len;
  ret = nanocbor_get_bstr(&arr, &serial_bytes,  &value_len);

  //decoded_cbor_cert
  uint32_t serial;
  if(3 == value_len) {
    serial= uint24_to_int(serial_bytes);
  } else if(4 == value_len) {
    serial= uint32_to_int(serial_bytes);
  } else { //
    if(2 == value_len) {
      serial= uint16_to_int(serial_bytes);
    } else {
      NRF_LOG_ERROR("Decode error, invalid serial number");
      return -1;
    }

  }

//  printf("ret: %d, serial: ", ret);
//  hdumps(serial_bytes, value_len);
//  printf("\n%u\n", ( unsigned int)serial);
  decoded_cbor_cert.serial_number = serial;

  const uint8_t *issuer; // = malloc(XIOT_MAX_ISSUER_LENGTH); //TODO
  ret = nanocbor_get_tstr(&arr, (const uint8_t **)&issuer,  &value_len);

//  printf("ret: %d, issuer of len %u\n", ret, (unsigned int)value_len);
  memcpy(decoded_cbor_cert.issuer, issuer, value_len);

//  for(i = 0; i < value_len; i++){
//    printf("%i\n", decoded_cbor_cert.issuer[i]);
//  }

  //printf("%s\n", decoded_cbor_cert.issuer);
  decoded_cbor_cert.issuer_length = value_len;

  uint32_t nba;
  ret = nanocbor_get_uint32(&arr, &nba);

//  tm_sec  int seconds after the minute  0-61*
//  tm_min  int minutes after the hour  0-59
//  tm_hour int hours since midnight  0-23
//  tm_mday int day of the month  1-31
//  tm_mon  int months since January  0-11
//  tm_year int years since 1900


//  printf("ret: %d, not before %u\n", ret, (unsigned int)nba);
  decoded_cbor_cert.not_before.tm_sec = nba % 60;
  int pSS = (nba - decoded_cbor_cert.not_before.tm_sec) / 60;
  decoded_cbor_cert.not_before.tm_min =  pSS % 60;
  int pMM = (pSS - decoded_cbor_cert.not_before.tm_min) / 60;
  decoded_cbor_cert.not_before.tm_hour = pMM % 24;
  int pHH = (pMM - decoded_cbor_cert.not_before.tm_hour) / 24;
  decoded_cbor_cert.not_before.tm_mday = pHH % 32;
  int pdd = (pHH - decoded_cbor_cert.not_before.tm_mday) / 32;
  decoded_cbor_cert.not_before.tm_mon = pdd % 13 -1; //TODO double check
  decoded_cbor_cert.not_before.tm_year = pdd / 13 + 100;

//  printf("%d %d %d %d %d %d\n", decoded_cbor_cert.not_before.tm_year+1900,
//      decoded_cbor_cert.not_before.tm_mon,
//      decoded_cbor_cert.not_before.tm_mday,
//      decoded_cbor_cert.not_before.tm_hour,
//      decoded_cbor_cert.not_before.tm_min,
//      decoded_cbor_cert.not_before.tm_sec);

  //  printf("%d %d %d %d %d %d\n", yy,mm,dd,HH,MM,SS);

//  int SS = nba % 60;
//  int pSS = (nba - SS) / 60;
//  int MM =  pSS % 60;
//  int pMM = (pSS - MM) / 60;
//  int HH = pMM % 24;
//  int pHH = (pMM - HH) / 24;
//  int dd = pHH % 32;
//  int pdd = (pHH - dd) / 32;
//  int mm = pdd % 13;
//  int yy = pdd / 13;
//  printf("%d %d %d %d %d %d\n", yy,mm,dd,HH,MM,SS);

  ret = nanocbor_get_uint32(&arr, &nba);
//  printf("ret: %d, not after %u\n", ret, (unsigned int)nba);

  decoded_cbor_cert.not_after.tm_sec = nba % 60;
  pSS = (nba - decoded_cbor_cert.not_after.tm_sec) / 60;
  decoded_cbor_cert.not_after.tm_min =  pSS % 60;
  pMM = (pSS - decoded_cbor_cert.not_after.tm_min) / 60;
  decoded_cbor_cert.not_after.tm_hour = pMM % 24;
  pHH = (pMM - decoded_cbor_cert.not_after.tm_hour) / 24;
  decoded_cbor_cert.not_after.tm_mday = pHH % 32;
  pdd = (pHH - decoded_cbor_cert.not_after.tm_mday) / 32;
  decoded_cbor_cert.not_after.tm_mon = pdd % 13 -1;  //TODO double check
  decoded_cbor_cert.not_after.tm_year = pdd / 13 + 100;

//  printf("%d %d %d %d %d %d\n", decoded_cbor_cert.not_after.tm_year+1900,
//      decoded_cbor_cert.not_after.tm_mon,
//      decoded_cbor_cert.not_after.tm_mday,
//      decoded_cbor_cert.not_after.tm_hour,
//      decoded_cbor_cert.not_after.tm_min,
//      decoded_cbor_cert.not_after.tm_sec);

//
//  int aSS = nba % 60;
//  int apSS = (nba - aSS) / 60;
//  int aMM =  apSS % 60;
//  int apMM = (apSS - aMM) / 60;
//  int aHH = apMM % 24;
//  int apHH = (apMM - aHH) / 24;
//  int add = apHH % 32;
//  int apdd = (apHH - add) / 32;
//  int amm = apdd % 13;
//  int ayy = apdd / 13;
//  printf("%d %d %d %d %d %d\n", ayy,amm,add,aHH,aMM,aSS);

  const uint8_t *subject;
  ret = nanocbor_get_bstr(&arr, &subject,  &value_len);

  memcpy(decoded_cbor_cert.subject, subject, value_len);
  decoded_cbor_cert.subject_length = value_len;
  decoded_cbor_cert.subject_ca = false;

//  printf("ret: %d, subject of len %u\n", ret, (unsigned int)value_len);
//  hdumps((const unsigned char*)decoded_cbor_cert.subject, value_len);
//  printf("\n");

  const uint8_t *pk;
  ret = nanocbor_get_bstr(&arr, &pk,  &value_len);
  if(!ret) { //TODO
    //return ret;
    NRF_LOG_INFO("ret was 0");
  }

//  printf("ret: %d, pk of len %u\n", ret, (unsigned int)value_len);
//  hdumps(pk, value_len);
//  printf("\n");

  x509_key_context *session_key_ctx;
  x509_key_context key_ctx;
  session_key_ctx = &key_ctx; //&session_data->key_ctx;
  ret = tls_credential_get(TLS_CREDENTIAL_ENROLLMENT_KEY, session_key_ctx, (unsigned short int*)&value_len); //getsockopt(SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_CA_CERTIFICATE, ptr_cert, &optlen);
  if(memcmp(key_ctx.pub_x, pk+1, ECC_DEFAULT_KEY_LEN)) {
    NRF_LOG_ERROR("Public key mismatch!\n");
    return -1;
  } //else we reuse the uncompressed keys that we already have:
  memcpy(decoded_cbor_cert.public_key, key_ctx.pub_x, ECC_DEFAULT_KEY_LEN);
  memcpy(decoded_cbor_cert.public_key+ECC_DEFAULT_KEY_LEN, key_ctx.pub_y, ECC_DEFAULT_KEY_LEN);

  int32_t extension;
  ret = nanocbor_get_int32(&arr, &extension);
  //printf("ret: %d, ext with val %u\n", ret, (unsigned int)extension);

  //https://www.alvestrand.no/objectid/2.5.29.html
//  2.5.29.15 - Key Usage
//  2.5.29.17 - Subject Alternative Name
//  2.5.29.19 - Basic Constraints
//  2.5.29.37 - Extended key usage
//  subjectAltName = 1
//  basicConstraints = 2 + cA
//  keyUsage = 3 + digitalSignature
//                + 2 * keyAgreement + 4 * keyCertSign
//  extKeyUsage = 10 + id-kp-serverAuth + 2 * id-kp-clientAuth
//                + 4 * id-kp-codeSigning + 8 * id-kp-OCSPSigning

  struct xiot_ext my_ext;

  if(1 == extension) {
    //subjectAltName not implemented
    return -1;
  }
  if(-3 == extension || 3 == extension) {
    //Basic Constraints not implemented
    return -1;
  }
  if(extension < -10 || 10 < extension) {
    //extKeyUsage not implemented
    return -1;
  }
  if(extension < -3 || 3 < extension) {
    //Key usage
    my_ext.oid = 15;
    if(extension < 0) {
      my_ext.critical = 1;
      extension = -extension;
    } else {
      my_ext.critical = 0;
    }

    if(4 == extension) {
      my_ext.length = strlen(ASN1_TAG_KEY_USAGE_DIGITAL_SIGN);
      //printf("my_ext.length %lu\n", my_ext.length);

      for(i = 0; i < my_ext.length; i++){
          my_ext.value[i] = ASN1_TAG_KEY_USAGE_DIGITAL_SIGN[i];
      }

    }
  }
  my_ext.next = NULL;
  decoded_cbor_cert.extensions = &my_ext;

  const uint8_t *signature;
  ret = nanocbor_get_bstr(&arr, &signature,  &value_len);
  //printf("ret: %d, sign of len %u\n", ret, (unsigned int)value_len);
  memcpy(decoded_cbor_cert.signature, signature, value_len);
//  hdumps(decoded_cbor_cert.signature, value_len);
//  printf("\n");
//  printf("Made it to here! ret = %d\n", ret);
  //xiot_construct(uint8_t* decompressed, xiot_cert_t* cert, uint8_t* ca_private)
  value_len = xiot_construct(decompressed_buffer, &decoded_cbor_cert, NULL);
//  hdumps(decompressed_buffer, value_len);
//  printf("\nvalue_len = %lu\n", value_len);

  return value_len;
}
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
int16_t
est_create_enroll_request_cbor(uint8_t *buffer, const uint16_t buf_len)
{
  int res = 0;
  int i = 0;

  memset(buffer, 1, buf_len);

//  pkcs10_request cbor_enroll_request;
//  pkcs10_init(&cbor_enroll_request);

//  printf("1\n");
  x509_key_context *session_key_ctx;
  x509_key_context key_ctx;
  session_key_ctx = &key_ctx; //&session_data->key_ctx;

    /* Generate new private and public keys to use in enrollment if needed */
    res = est_generate_session_keys(session_key_ctx);
    if(res < 0) {
      NRF_LOG_ERROR("est_create_enroll_request: generate session keys failed\n");
      return 0;
    }

  /* Set EUI64 subject and attribute set for the request */
  //Here possibly call needed function to get mac id:
  uint8_t value[XIOT_EUI64_SHORT_LEN];
  for(i=0; i < XIOT_EUI64_SHORT_LEN; i++) {
    value[i] = client_mac_id[i];
  }

//  const int CBOR_ENROLL_MAX_LEN = 200;
//  uint8_t enroll_bstr[CBOR_ENROLL_MAX_LEN];
  memset(buffer, 0, buf_len);
  nanocbor_encoder_t nc;
  nanocbor_encoder_init(&nc, buffer, buf_len);
  nanocbor_put_bstr(&nc, value, XIOT_EUI64_SHORT_LEN);
  //size_t len_man_bstr = nanocbor_encoded_len(&nc);

//  printf("3\n");
  /* Set the compressed public key */
  uint8_t compressed_xy[ECC_DEFAULT_KEY_LEN+1];
  compressed_xy[0] = 2 + ( session_key_ctx->pub_y[ECC_DEFAULT_KEY_LEN-1] & 1 );// = sign of pub_y
  memcpy(compressed_xy+1,session_key_ctx->pub_x,ECC_DEFAULT_KEY_LEN);
  compressed_xy[0] = 2 + ( session_key_ctx->pub_y[ECC_DEFAULT_KEY_LEN-1] & 1 );// = sign of pub_y
  nanocbor_put_bstr(&nc, compressed_xy, ECC_DEFAULT_KEY_LEN+1);

//  uint8_t uncompressed_xy[1+2*ECC_DEFAULT_KEY_LEN];
//  uncompressed_xy[0] = 4;
//  memcpy(uncompressed_xy+1, session_key_ctx->pub_x, ECC_DEFAULT_KEY_LEN);
//  memcpy(uncompressed_xy+1+ECC_DEFAULT_KEY_LEN, session_key_ctx->pub_y, ECC_DEFAULT_KEY_LEN);
//  nanocbor_put_bstr(&nc, uncompressed_xy, 1+2*ECC_DEFAULT_KEY_LEN);


//  printf("4: nc.len %u\n", (unsigned int)nc.len);
  /* Sign the resulting cbor data */
  /* Generate the signature */
  unsigned char rs_buf[2*ECC_DEFAULT_SIGN_LEN];

  res = create_ecc_signature(buffer, nc.len, rs_buf, ECC_DEFAULT_SIGN_LEN, rs_buf+ECC_DEFAULT_SIGN_LEN, ECC_DEFAULT_SIGN_LEN);
  //res = create_ecc_signature(buffer, nc.len, r_buf, ECC_DEFAULT_SIGN_LEN, s_buf, ECC_DEFAULT_SIGN_LEN);
  //res = create_ecc_signature(buffer, 32, r_buf, ECC_DEFAULT_SIGN_LEN, s_buf, ECC_DEFAULT_SIGN_LEN);

  if(res < 0) {
    NRF_LOG_ERROR("est_create_enroll_request: generate signature failed\n");
    return -1;
  }
//  printf("5\n");
  /* Encode the signature components r and s as a bstr */
  nanocbor_put_bstr(&nc, rs_buf, 2*ECC_DEFAULT_SIGN_LEN);
  //nanocbor_put_bstr(&nc, r_buf, ECC_DEFAULT_SIGN_LEN);
//  printf("6: nc.len %u\n", (unsigned int)nc.len);
  return nc.len;
}
/*----------------------------------------------------------------------------*/
#else
int cbor_decompress_cert(uint8_t *buffer, uint16_t buf_len, uint8_t *decompressed_buffer)
{
  return -1;
}
#endif

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/**
 * raw_certificate_buffer: To keep the decoded cert in binary format. Handed back to the client
 */
int
est_process_enroll_response(uint8_t *incoming_buffer, const uint16_t buf_len, unsigned char *path, uint8_t *raw_certificate_buffer, int *cert_len)
{
  uint8_t *buffer = NULL;
  int res = 0;

  uint16_t decoded_buf_len;

  if(incoming_buffer[0] != 0x30) {
    //Try to decompress!
    res = cbor_decompress_cert(incoming_buffer, buf_len, raw_certificate_buffer);
    if(res < 0) {
      NRF_LOG_ERROR("EST ERROR - est_process_enroll_response: Could not parse certificate\n");
      return res;
    }
    buffer = raw_certificate_buffer;
    decoded_buf_len = res;

  } else {
    buffer = incoming_buffer;
    decoded_buf_len = buf_len;
  }

  static cms_signed_data sdata; //todo?
  /* CMS decode the response */
  cms_init(&sdata);

  if(res) {
    uint8_t **pos = &buffer;
    uint8_t *certificates_end;
    certificates_end = *pos + decoded_buf_len;
    res = x509_decode_certificate_sequence(pos, certificates_end, &sdata.head);
  } else {
    res = cms_decode_content_info(buffer, decoded_buf_len, raw_certificate_buffer, cert_len, &sdata);
  }


  if(res < 0) {
    NRF_LOG_ERROR("EST ERROR - est_process_enroll_response: Could not decode cms\n");
    return res;
  }

//  if(1) {
//    return -444;
//  }

  /* If the certificate chain is received, remove all but the enrolled cert. */
  if(sdata.head->next != NULL) {
    x509_memb_remove_certificates(sdata.head->next);
    sdata.head->next = NULL;
  }
  /* Check if subject in certificate received is the same as in the request */
  res = est_check_enroll_cert_subject(sdata.head);
  if(res < 0) {
    NRF_LOG_ERROR("EST ERROR - est_process_enroll_response: Could not check cert subject\n");
    return res;
  }

//  if(1) {
//    return -555;
//  }

  /* Certificate verification */
  x509_certificate *ptr_cert = malloc(sizeof(x509_certificate)); //NULL; // = malloc(sizeof(x509_certificate)); //&target_cert;


  uint16_t optlen;
  res = tls_credential_get(TLS_CREDENTIAL_CA_CERTIFICATE, ptr_cert, &optlen); //getsockopt(SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_CA_CERTIFICATE, ptr_cert, &optlen);
  if(res < 0) {
    NRF_LOG_ERROR("est_process_enroll_response: could not retrieve CA cert for verification\n");
    return -666;
  }
//  printf("ptr_cert->pk_info.subject_public_key.bit_string\n");
//  hdumps(ptr_cert->pk_info.subject_public_key.bit_string, 72);
  /* Find the end of the ca path, and attach the newly decoded cert there */
  while(ptr_cert->next != NULL) {
    //printf("Is there a chain??\n");
    ptr_cert = ptr_cert->next;
  }
  ptr_cert->next = sdata.head;

  NRF_LOG_DEBUG("Certificate path validation\n");
#if PLATFORM_HAS_TIME
  res = x509_verify_certificate_path(ptr_cert->next, ptr_cert, x509_get_ctime());
#else
  NRF_LOG_WARNING("Verify without time\n");
  res = x509_verify_certificate_path(ptr_cert->next, ptr_cert, NULL);
#endif

  if(res < 0) {
    NRF_LOG_ERROR("EST ERROR - COULD NOT VERIFY ENROLLED Certificate\n");
    return -777;
  } else {
    NRF_LOG_DEBUG("Enrolled certificate verified\n");
  }
  /* Reset the end of the path */
  ptr_cert->next = NULL;

  /* Write certificate to session buffer */
  //res = est_cert_to_session_buffer(sdata.head, EST_CERT_IS_NOT_CA);
//  res = tls_credential_add(TLS_CREDENTIAL_ENROLLED_CERTIFICATE, sdata.head, sizeof(sdata.head)); //setsockopt(SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_ENROLLED_CERTIFICATE, sdata.head, sizeof(sdata.head));
//  if(res < 0) {
//    NRF_LOG_ERROR("EST ERROR - est_process_enroll_response: Could not write new certificate to memory\n");
//    return res;
//  }
  //


  memset(buffer, 0, buf_len);
  return 0;
}
/*----------------------------------------------------------------------------*/
int16_t
est_create_enroll_request(uint8_t *buffer, uint16_t buf_len)
{
//#if USE_CBOR_ENCODING
//  return est_create_enroll_request_cbor(buffer, buf_len);
//#endif

  int res = 0;
  memset(buffer, 0, buf_len);

  pkcs10_request enroll_request;
  pkcs10_init(&enroll_request);
  /* Set EUI64 subject and attribute set for the request */
  uint8_t value[X509_EUI64_SUBJECT_SIZE];
  res = pkcs10_set_default_subject(&enroll_request, value, ENROLL_SUBJECT_SIZE); //was: X509_EUI64_SUBJECT_SIZE

  if(res < 0) {
    NRF_LOG_ERROR("est_cer: default subject failed\n");
    return -1;
  }
  res = pkcs10_set_default_attribute_set(&enroll_request, NULL, 0);

  if(res < 0) {
    NRF_LOG_ERROR("est_cer: default attribute set failed\n");
    return -2;
  }

  x509_key_context *session_key_ctx;
  x509_key_context key_ctx;
  session_key_ctx = &key_ctx; //&session_data->key_ctx;


  /* Generate new private and public keys to use in enrollment if needed */
  res = est_generate_session_keys(session_key_ctx);
  NRF_LOG_FLUSH();
  if(res < 0) {
    NRF_LOG_ERROR("est_cer: generate session keys failed\n");
    return -3;
  }

  /* Set key context for the request */
  enroll_request.key_ctx = session_key_ctx;


  /* PKCS10 encode the request in the buffer provided */
  /* FIXME: pkcs10_encode() places encoded PKCS10 msg at the *end* of buffer,
    in order to fullfil the requirement for calling est_base64_encode_block_inplace()
    immediately. When base64 encoding is disabled, pkcs10_encode *should* output the
    PKCS10 msg at the *beginning* of the buffer. */
  NRF_LOG_FLUSH();
  res = pkcs10_encode(&enroll_request, buffer, buf_len);
  if(res < 0) {
    NRF_LOG_ERROR("est_create_enroll_request: pkcs10 encode failed\n");
    return -4;
  }

  // HACK
  memmove(buffer, buffer+buf_len-res, res);
//  printf("\nDUMP\n");
//  hdumps(buffer, res);
//  printf("\n");
  return res;
}
/*----------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
void
hdumps(const unsigned char *buf, int len)
{
  while(len-- > 0) {
    printf("%02x", *buf++);
  }
}

/*---------------------------------------------------------------------------*/
