/*
 * Copyright (c) 2015, Swedish Institute of Computer Science
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
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *          Implementation of functions to encode PKCS #10 messages
 *
 * \author
 *         Rúnar Már Magnússon  <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#include "est-pkcs10.h"

#include <string.h>

#include "est-asn1.h"
#include "est-oid.h"
#include "est-x509.h"
#include "stdio.h"

#if STANDALONE_VERSION
#include "standalone_log.h"
#include "util/nrf_log_wrapper.h"
#define LOG_MODULE "pkcs"
#ifdef LOG_CONF_LEVEL_PKCS
#define LOG_LEVEL LOG_CONF_LEVEL_PKCS
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif
#include "util/standalone_log.h"
#else //== not standalone version
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
//#define NRF_LOG_MODULE_NAME mwrap
//NRF_LOG_MODULE_REGISTER();
//#include "nrf_log_wrapper.h"
#endif

/*----------------------------------------------------------------------------*/
void
pkcs10_init(pkcs10_request *req)
{
  memset(req, 0, sizeof(pkcs10_request));

#if EST_DEBUG_PKCS10
  NRF_LOG_INFO("pkcs10_init request at %p initialized\n", req);
#endif
}
/*----------------------------------------------------------------------------*/
int
pkcs10_set_default_subject(pkcs10_request *req, uint8_t *value, uint16_t value_length)
{
#if TEST_ENROLL_SUBJECT
  return x509_set_subject(&req->subject, value, value_length);
#else
  return x509_set_eui64_subject(&req->subject, value, value_length);
#endif
}
/*----------------------------------------------------------------------------*/
int
pkcs10_set_default_attribute_set(pkcs10_request *req, uint8_t *value, uint16_t value_length)
{

  /* TODO: (DTLS Channel Binding) For now we do not use the optional attribute
   * set but in the future we might need to use it e.g. for DTLS channel binding */
  if(value == NULL) {
    req->attribute_set.value = NULL;
    req->attribute_set.tag = 0x00;
    req->attribute_set.length = 0;
  } else {
    req->attribute_set.value = value;
    req->attribute_set.tag = (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT);
    req->attribute_set.length = value_length;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
pkcs10_encode(pkcs10_request *req, uint8_t *buffer, uint16_t len)
{
  int res = 0;

  /* Temporary buffer before we calculate the signature over */
  uint8_t request_info[PKCS10_MAX_REQUEST_INFO_LENGTH];
  memset(request_info, 0, sizeof(request_info));

  uint16_t length = 0, data_len = 0, sign_len = 0;
  uint8_t *start = buffer;
  uint8_t *pos = buffer + len;
  uint8_t *sign_start;
  uint8_t *data_start = request_info;
  uint8_t *data_pos = request_info + sizeof(request_info);

  asn1_tlv sign_algo;

  /* Encode the Certification Request Info */
  res = pkcs10_encode_request_info(&data_pos, data_start, req->key_ctx, &req->subject, &req->attribute_set);
  if(res < 0) {
    NRF_LOG_ERROR("pkcs10_encode: Could not enc CertReqInfo\n");
    return res;
  }
  data_len = res;
  length += data_len;

  /* Create and encode the signature */
  data_start = request_info + (PKCS10_MAX_REQUEST_INFO_LENGTH - data_len);
  /* Sign request info and write to original buffer */
  res = x509_encode_signature(&pos, start, data_start, data_len, req->key_ctx);
  if(res < 0) {
    NRF_LOG_ERROR("PKCS #10 ERROR - pkcs10_encode: Could not sign request\n");
    return res;
  }
  sign_len = res;
  length += sign_len;
  sign_start = buffer + len - sign_len;

  /* Write signature algorithm identifier */
  /* Create and Encode the signature algorithm identifier */
  switch(req->key_ctx->sign) {
  case ECDSA_WITH_SHA256:
    sign_algo.tag = ASN1_TAG_OID;
    sign_algo.value = (uint8_t *)OID_ALGORITHM_ECDSA_WITH_SHA256;
    sign_algo.length = OID_LENGTH(OID_ALGORITHM_ECDSA_WITH_SHA256);
    break;
  default:
    NRF_LOG_INFO("pkcs10_encode: Unknown signature algorithm %u\n", req->key_ctx->sign);
    return -1;
  }

  /* Encode the signature algorithm identifier */
  res = x509_encode_algorithm_identifier(&pos, start, &sign_algo, NULL);
  if(res < 0) {
    NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode: Could not encode signatureAlgorithm\n");
    return res;
  }
  length += res;

  /* Copy request info into original buffer */
  pos -= data_len;
  memcpy(pos, data_start, data_len);

  /* Encode the CertificationRequest sequence */
  res = asn1_encode_length_and_tag(&pos, start,
                                   (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT),
                                   length);
  if(res < 0) {
    NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode: Could not encode CertificationRequest sequence \n");
    return res;
  } else {
    length += res;
  }

  /* Verify the signature that we created */
  res = x509_verify_signature(data_start, data_len, sign_start, sign_len, req->key_ctx, 1); //TODO
  //res = x509_verify_signature(data_start, data_len, sign_start, sign_len, NULL);
  if(res < 0) {
    NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode: Signature verification failed \n");
    return res;
  } else {
    NRF_LOG_INFO("PKCS #10 Signature verification SUCCESSFUL\n");
  }

#if EST_DEBUG_PKCS10
  NRF_LOG_INFO("pkcs10_encode encoded %d bytes\n", (int)length);
#endif

  return length;
}
/*----------------------------------------------------------------------------*/
int
pkcs10_encode_request_info(uint8_t **pos, uint8_t *start, x509_key_context *key_ctx,
                           asn1_tlv *subject, asn1_tlv *attributes)
{
  int res = 0;
  uint16_t length = 0;

  /* Encode the attributes*/
  if(attributes == NULL || attributes->length == 0) {
    /* [0] { } = A0 00 was used when no attributes where specified */
    res = asn1_encode_length_and_tag(pos, start,
                                     (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT), 0);
    if(res < 0) {
      NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode [0] \n");
      return res;
    } else {
      length += res;
    }
  } else {
    res = asn1_encode_buffer(pos, start, attributes->value, attributes->length);
    if(res < 0) {
      NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode attributes \n");
      return res;
    }
    length += res;

    res = asn1_encode_length_and_tag(pos, start, attributes->tag, attributes->length);
    if(res < 0) {
      NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode attributes \n");
      return res;
    }
    length += res;

    /* [0] { } = A0 00 was used when no attributes where specified */
    res = asn1_encode_length_and_tag(pos, start,
                                     (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT), length);
    if(res < 0) {
      NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode [0] \n");
      return res;
    } else {
      length += res;
    }
  }

  /* encode the subjectPKInfo */
  res = x509_encode_pk_info(pos, start, key_ctx);
  if(res < 0) {
    NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode subjectPKInfo \n");
    return res;
  }
  length += res;

  /* Encode the subject */
  res = x509_encode_subject(pos, start, subject);
  if(res < 0) {
    NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode subject \n");
    return res;
  }
  length += res;

  /* Encode the version,  */
  res = asn1_encode_integer(pos, start, PKCS10_VERSION_0);
  if(res < 0) {
    NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode version \n");
    return res;
  }
  length += res;

  /* Encode the  CertificationRequestInfo sequence */
  res = asn1_encode_length_and_tag(pos, start,
                                   (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT),
                                   length);
  if(res < 0) {
    NRF_LOG_INFO("PKCS #10 ERROR - pkcs10_encode_request_info: Could not encode CertificationRequestInfo \n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_PKCS10
  NRF_LOG_INFO("pkcs10_encode_request_info encoded %d bytes\n", (int)length);
#endif

  return length;
}
/*----------------------------------------------------------------------------*/
