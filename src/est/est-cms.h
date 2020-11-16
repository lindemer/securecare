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
 *          Structures for CMS SignedData for the EST protocol

 * \author
 *         Rúnar Már Magnússon <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#ifndef EST_CMS_H
#define EST_CMS_H

#include "est-asn1.h"
#include "est-x509.h"

#define CMS_DBG(...)

#define DIGEST_ALG_OID_SIZE 16

#define CMS_VERSION_0 0
#define CMS_VERSION_1 1
#define CMS_VERSION_2 2
#define CMS_VERSION_3 3
#define CMS_VERSION_4 4
#define CMS_VERSION_5 5

/**
 * Container for decoded CMS SignedData
 * SignedData ::= SEQUENCE {
 *      version CMSVersion,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      encapContentInfo EncapsulatedContentInfo,           (NOT USED)
 *      certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,   (NOT USED)
 *      signerInfos SignerInfos }                           (NOT USED)
 *
 * CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
 *
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *
 *
 * EncapsulatedContentInfo ::= SEQUENCE {
 *      eContentType ContentType,
 *      eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *
 * CertificateSet ::= SET OF CertificateChoices
 * CertificateChoices ::= CHOICE {
 *      certificate Certificate,
 *      extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
 *      v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
 *      v2AttrCert [2] IMPLICIT AttributeCertificateV2,
 *      other [3] IMPLICIT OtherCertificateFormat }
 * OtherCertificateFormat ::= SEQUENCE {
 *      otherCertFormat OBJECT IDENTIFIER,
 *      otherCert ANY DEFINED BY otherCertFormat }
 *
 * RevocationInfoChoices ::= SET OF RevocationInfoChoic
 * RevocationInfoChoice ::= CHOICE {
 *      crl CertificateList,
 *      other [1] IMPLICIT OtherRevocationInfoFormat }
 *
 * We only need to use version and  CertificateSet in the simple PKI response
 */
typedef struct cms_signed_data {
  asn1_tlv signed_data;   /* Container for the CMS data */

  uint8_t version;

  x509_certificate *head;   /* The first certificate in a chain of certificates
                             * or the only certificate */
} cms_signed_data;

/**
 * Zero initializes a cms_signed_data structure
 * @param cms the structure to initialize
 */
void cms_init(cms_signed_data *cms);

/**
 * Decode a CMS ContentInfo
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content [0] EXPLICIT ANY DEFINED BY contentType }
 *
 * @param buffer the buffer that stores the CMS ContentInfo
 * @param buf_len the length of the ContentInfo
 * @param cms the structure to store the decoded ContentInfo
 * @return 0 if successful, -1 otherwise
 */
//int cms_decode_content_info(uint8_t *buffer, uint16_t buf_len, cms_signed_data *cms);
int cms_decode_content_info(uint8_t *buffer, uint16_t buf_len, uint8_t *cert_buf, int *cert_len, cms_signed_data *cms);

/**
 * Function to decode SignedData and stores the decoded information in cms
 *
 * SignedData ::= SEQUENCE {
 *      version CMSVersion,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      encapContentInfo EncapsulatedContentInfo,           (NOT USED)
 *      certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,   (NOT USED)
 *      signerInfos SignerInfos }
 *                         (NOT USED)
 * @param pos the start of the SignedData
 * @param end the end of the SignedData
 * @param certificates_start the start of the certificate data
 * @param cms the structure to store the decoded information
 * @return 0 if successful, -1 otherwise
 */
int cms_decode_signed_data(uint8_t **pos, uint8_t *end, uint8_t *cert_buf, int *cert_len, cms_signed_data *cms);

/**
 * Verifies CMSVersion
 *
 * CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
 *
 * @param version the version to verify
 * @return 0 if supported, -1 otherwise
 */
int cms_verify_version(uint32_t version);

/**
 * Decodes CMSVersion
 *
 * @param pos start of the CMSVersion
 * @param end the end of CMSVersion
 * @param version the variable to store the result
 * @return 0 if successful, -1 otherwise
 */
int cms_decode_version(uint8_t **pos, uint8_t *end, uint32_t *version);

/**
 * Decode EncapsulatedContentInfo
 *
 * EncapsulatedContentInfo ::= SEQUENCE {
 *      eContentType ContentType,
 *      eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *
 * @param pos the start of EncapsulatedContentInfo
 * @param end the end of EncapsulatedContentInfo
 * @param str_oid the OID of the eContentType that we expect
 * @return 0 if the decoding and verification was successful, -1 otherwise
 */
int cms_decode_and_verify_encapContentInfo(uint8_t **pos, uint8_t *end, char *str_oid);

#endif /* EST_CMS_H */
