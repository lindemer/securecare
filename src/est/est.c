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

#include <stdio.h>
#include <string.h>


#include "est.h"
#include "est-cms.h"
#include "est-pkcs10.h"
#include "est-x509.h"

//#include "os/net/security/other-ecc/other-ecc.h"


#include "../util/log.h"
#include "mbedtls-wrapper.h"
#define LOG_MODULE "est"
#ifdef LOG_CONF_LEVEL_EST
#define LOG_LEVEL LOG_CONF_LEVEL_EST
#else
#define LOG_LEVEL LOG_LEVEL_DBG
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
    LOG_ERR("EST ERROR - est_cert_to_coffee: NULL pointer cert_in\n");
    return -1;
  }

  int res = 0;

  if(is_ca_cert) {
    res = x509_write_certificate_to_file(cert_in, EXPLICIT_TA);

    if(res < 0) {
      LOG_ERR("EST ERROR - est_cert_to_coffee: Could not write Explicit TA to file\n");
      return res;
    }

    if(cert_in->next != NULL) {
      res = x509_write_certificate_to_file(cert_in->next, EXPLICIT_PATH);

      if(res < 0) {
        LOG_ERR("EST ERROR - est_cert_to_coffee: Could not write Explicit PATH to file\n");
        return res;
      }
    }
  } else {
    res = x509_write_certificate_to_file(cert_in, MY_CERTIFICATE);

    if(res < 0) {
      LOG_ERR("EST ERROR - est_cert_to_coffee: Could not write MY Certificate to file\n");
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
    LOG_DBG("Found a not self signed cert, swap certificate order!\n");
    x509_certificate *tmp_cert = cms->head->next;
    cms->head->next = NULL;
    int i = 0;
    while(tmp_cert != NULL) {
      LOG_DBG("%d\n", i++);
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
  res = x509_set_eui64_subject(&eui64_subject, value, X509_EUI64_SUBJECT_SIZE);
  if(res < 0) {
    LOG_ERR("EST ERROR - est_check_enroll_cert_subject: Could not set eui64 subject\n");
    return res;
  }
  res = x509_verify_subject(&eui64_subject, &cert_in->subject_name);
  if(res < 0) {
    LOG_ERR("EST ERROR - est_check_enroll_cert_subject: Subject in certificate not the eui64 subject\n");
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

    LOG_DBG("est_generate_session_keys - SESSION HAS NO KEYS, GEN NEW\n");
    //TODO - test
    generate_enrollment_keys(key_ctx);

  } else {

    LOG_DBG("est_generate_session_keys - SESSION HAS KEYS, USE TO ENROLL\n");
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
    LOG_ERR("est_process_cacerts_response: Could not decode cms\n");
    return res;
  }

  /* Check if the order of certificates is correct */
  res = est_check_cacerts_order(&sdata);
  if(res < 0) {
    LOG_ERR("est_process_cacerts_response: Could not set correct order of certificates\n");
    return res;
  }

  /* TODO: (Contiki Time Syncronization) Get the current network time and use
     it in x509_verify_certificate_path to verify the validity of the certificates */

  LOG_DBG("CA Certificate path validation\n");
  res = x509_verify_certificate_path(sdata.head->next, sdata.head, x509_get_ctime());

  if(res < 0) {
    LOG_ERR("COULD NOT VERIFY CACERTS PATH\n");
    return res;
  } else {
    LOG_DBG("Cacerts path verified\n");
  }

  /* Write CA certificates to session buffer */
  if (NULL != path) {
    res = 0; //est_cert_to_coffee(sdata.head, EST_CERT_IS_CA);
    if(res < 0) {
      LOG_ERR("EST ERROR - est_process_cacerts_response: Could not write to coffee file system\n");
      return res;
    }
  else {
    LOG_DBG("Copying cacerts to client buffer\n");
    memcpy(result_buffer, sdata.head, sdata.head->tbs_cert_len+sdata.head->sign_len);
  }
  //TODO: should we replace existing CA, or create another one

//  res = cng_setsockopt(fd, SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_CA_CERTIFICATE, sdata.head, sdata.head->tbs_cert_len+sdata.head->sign_len);
//  if(res < 0) {
//    LOG_ERR("est_process_cacerts_response: Could not write TLS_CREDENTIAL_CA_CERTIFICATE to buffer\n");
//    return res;
//  }
  }
  memset(buffer, 0, buf_len);
  return 0;
}
/*----------------------------------------------------------------------------*/
int
est_process_enroll_response(uint8_t *buffer, uint16_t buf_len, unsigned char *path, uint8_t *raw_certificate_buffer, int *cert_len)
{
  int res;
  cms_signed_data sdata;

  /* CMS decode the response */
  cms_init(&sdata);
  res = cms_decode_content_info(buffer, buf_len, raw_certificate_buffer, cert_len, &sdata);
  if(res < 0) {
    LOG_ERR("EST ERROR - est_process_enroll_response: Could not decode cms\n");
    return res;
  }
  /* If the certificate chain is received, remove all but the enrolled cert. */
  if(sdata.head->next != NULL) {
    x509_memb_remove_certificates(sdata.head->next);
    sdata.head->next = NULL;
  }
  /* Check if subject in certificate received is the same as in the request */
  res = est_check_enroll_cert_subject(sdata.head);
  if(res < 0) {
    LOG_ERR("EST ERROR - est_process_enroll_response: Could not check cert subject\n");
    return res;
  }

  /* Certificate verification */
  x509_certificate *ptr_cert = malloc(sizeof(x509_certificate)); //&target_cert;

  uint16_t optlen;
  res = tls_credential_get(TLS_CREDENTIAL_CA_CERTIFICATE, ptr_cert, &optlen); //getsockopt(SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_CA_CERTIFICATE, ptr_cert, &optlen);
  if(res < 0) {
    LOG_ERR("est_process_enroll_response: could not retrieve CA cert for verification\n");
    return -1;
  }

  /* Find the end of the ca path */
  while(ptr_cert->next != NULL) {
    ptr_cert = ptr_cert->next;
  }
  ptr_cert->next = sdata.head;

  LOG_DBG("Certificate path validation\n");
  res = x509_verify_certificate_path(ptr_cert->next, ptr_cert, x509_get_ctime());

  if(res < 0) {
    LOG_ERR("EST ERROR - COULD NOT VERIFY ENROLLED Certificate\n");
    return res;
  } else {
    LOG_DBG("Enrolled certificate verified\n");
  }
  /* Reset the end of the path */
  ptr_cert->next = NULL;

  /* Write certificate to session buffer */
  //res = est_cert_to_session_buffer(sdata.head, EST_CERT_IS_NOT_CA);
//  res = tls_credential_add(TLS_CREDENTIAL_ENROLLED_CERTIFICATE, sdata.head, sizeof(sdata.head)); //setsockopt(SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_ENROLLED_CERTIFICATE, sdata.head, sizeof(sdata.head));
//  if(res < 0) {
//    LOG_ERR("EST ERROR - est_process_enroll_response: Could not write new certificate to memory\n");
//    return res;
//  }
  //


  memset(buffer, 0, buf_len);
  return 0;
}
/*----------------------------------------------------------------------------*/
uint16_t
est_create_enroll_request(uint8_t *buffer, uint16_t buf_len)
{
  int res = 0;
  memset(buffer, 0, buf_len);

  pkcs10_request enroll_request;
  pkcs10_init(&enroll_request);
  /* Set EUI64 subject and attribute set for the request */
  uint8_t value[X509_EUI64_SUBJECT_SIZE];
  res = pkcs10_set_default_subject(&enroll_request, value, X509_EUI64_SUBJECT_SIZE);

  if(res < 0) {
    LOG_ERR("EST ERROR - est_create_enroll_request: default subject failed\n");
    return 0;
  }
  res = pkcs10_set_default_attribute_set(&enroll_request, NULL, 0);

  if(res < 0) {
    LOG_ERR("est_create_enroll_request: default attribute set failed\n");
    return 0;
  }
  x509_key_context *session_key_ctx;
#if EST_WITH_COFFEE
  x509_key_context key_ctx;
  session_key_ctx = &key_ctx;
#else
  x509_key_context key_ctx;
  session_key_ctx = &key_ctx; //&session_data->key_ctx;
#endif

  /* Generate new private and public keys to use in enrollment if needed */
  res = est_generate_session_keys(session_key_ctx);
  if(res < 0) {
    LOG_ERR("est_create_enroll_request: generate session keys failed\n");
    return 0;
  }

  /* Set key context for the request */
  enroll_request.key_ctx = session_key_ctx;


  /* PKCS10 encode the request in the buffer provided */
  /* FIXME: pkcs10_encode() places encoded PKCS10 msg at the *end* of buffer,
    in order to fullfil the requirement for calling est_base64_encode_block_inplace()
    immediately. When base64 encoding is disabled, pkcs10_encode *should* output the
    PKCS10 msg at the *beginning* of the buffer. */

  res = pkcs10_encode(&enroll_request, buffer, buf_len);
  if(res < 0) {
    LOG_ERR("est_create_enroll_request: pkcs10 encode failed\n");
    return 0;
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
