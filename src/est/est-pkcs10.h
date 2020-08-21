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
 *          Structures for PKCS#10 Certificate Signing Requests
 *          for the EST protocol

 * \author
 *         Rúnar Már Magnússon <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#ifndef EST_CSR_H
#define EST_CSR_H

#include "est-asn1.h"
#include "est-x509.h"


#define PKCS10_DBG(...)


#define PKCS10_VERSION_0 0

/* Needs to be increased if default subject is not used or if attributes are used */
#define PKCS10_MAX_REQUEST_INFO_LENGTH 144

/**
 * Container for encoding PKCS #10 Certificate Signing Request
 * CertificationRequest ::= SEQUENCE {
 *         certificationRequestInfo CertificationRequestInfo,
 *         signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *         signature          BIT STRING }
 */
typedef struct pkcs10_request {
  x509_key_context *key_ctx;   /**<- The key context used to sign the request */

  /* CertificationRequestInfo */
  asn1_tlv subject;
  asn1_tlv attribute_set;
} pkcs10_request;

/**
 * Sets the default subject used in PKCS #10 requests (default EUI-64 identifier)
 * @param req points to the request to set the subject of
 * @param value buffer that can store the subject
 * @param value_length length of the value
 * @return 0 if successful, -1 otherwise
 */
int pkcs10_set_default_subject(pkcs10_request *req, uint8_t *value, uint16_t value_length);

/**
 * Sets the default attributes used in the PKCS #10 request (default empty)
 * @param req the request to set the attributes of
 * @param value the attribute value
 * @param value_length the length of the attribute
 * @return 0 if successful, -1 otherwise
 */
int pkcs10_set_default_attribute_set(pkcs10_request *req, uint8_t *value, uint16_t value_length);

/**
 * Zero initializes the Certificate signing request.
 * @param req the CSR to initialize
 */
void pkcs10_init(pkcs10_request *req);

/**
 *
 * Encodes the certificate signing request from req to the buffer of length len
 *
 * @param req the CSR structure that holds the request information to encode
 * @param buffer the buffer to write to
 * @param len the length of the buffer
 * @return the encoded length if successful, -1 otherwise
 */
int pkcs10_encode(pkcs10_request *req, uint8_t *buffer, uint16_t len);

/**
 * Encode the CertificationRequestInfo
 * CertificationRequestInfo ::= SEQUENCE {
 *         version       INTEGER { v1(0) } (v1,...),
 *         subject       Name,
 *         subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *         attributes    [0] Attributes{{ CRIAttributes }}}
 *
 * Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 * Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *         type   ATTRIBUTE.&id({IOSet}),
 *         values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})}
 *
 * @param pos the next position to write to.
 * @param start the position that we won't write over
 * @param key_ctx the key context to use to sign the request
 * @param subject the subject that will be used in the enrolled certificate
 * @param attributes any additional attributes in the request
 * @return The length of the encoded request info if successful -1 otherwise.
 */
int pkcs10_encode_request_info(uint8_t **pos, uint8_t *start, x509_key_context *key_ctx,
                               asn1_tlv *subject, asn1_tlv *attributes);

#endif /* EST_CSR_H */
