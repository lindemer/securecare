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
 *         Implementation of the functions to decode CMS SignedData
 *         for the EST protocol
 *
 * \author
 *         Rúnar Már Magnússon <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#include <stdio.h>
#include "est.h"
#include "est-cms.h"

#include "est-asn1.h"
#include "est-oid.h"
#include "est-x509.h"


#include "log.h"

#define LOG_MODULE "cms"
#ifdef LOG_CONF_LEVEL_EST_CMS
#define LOG_LEVEL LOG_CONF_LEVEL_EST_CMS
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif

/*----------------------------------------------------------------------------*/
void
cms_init(cms_signed_data *cms)
{
  memset(cms, 0, sizeof(cms_signed_data));
#if EST_DEBUG_CMS
  LOG_DBG("CMS Response at %p initialized\n", cms);
#endif
}
/*----------------------------------------------------------------------------*/
int
cms_decode_content_info(uint8_t *buffer, uint16_t buf_len, cms_signed_data *cms)
{
  int res = 0;
  uint8_t *pos;
  uint8_t *end;
  uint16_t length = 0;
  asn1_tlv content_type_oid;

  /* Initialize pointers */
  pos = buffer;
  end = buffer + buf_len;

  /* Decode ContentInfo Sequence */
  res = asn1_decode_tag(&pos, end, &length, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_ERR("cms_decode_content_info: Malformed ContentInfo\n");
    return res;
  }

  LOG_DBG("cms_decode_content_info - ContentInfo Sequence decoded\n");

  /* Decode ContentType OID */
  res = asn1_decode_tag(&pos, end, &content_type_oid.length, ASN1_TAG_OID);
  if(res < 0) {
    LOG_ERR("cms_decode_content_info: Could not decode ContentType OID\n");
    return res;
  }
  content_type_oid.tag = ASN1_TAG_OID;
  content_type_oid.value = pos;

  /* Advance to the next tag */
  pos += content_type_oid.length;

  LOG_DBG("cms_decode_content_info - ContentType OID decoded\n");

  /* Content */
  if(oid_cmp(OID_ID_SIGNED_DATA, content_type_oid.value, content_type_oid.length) == 0) {
    LOG_DBG("cms_decode_content_info - ContentType is SignedData\n");

    /* Remove the explicit tag if it is there */
    res = asn1_decode_tag(&pos, end, &length,
                          (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT));
    if(res < 0) {
      LOG_WARN("Explicit tag missing, try to continue\n");
    }

    res = cms_decode_signed_data(&pos, end, cms);

    if(res < 0) {
      LOG_ERR("cms_decode_content_info - Could not decode signed data\n");
      return res;
    }

    LOG_DBG("cms_decode_content_info - Signed Data Decoded\n");

  } else {
    LOG_ERR("cms_decode_content_info - Unsupported or unknown tag\n");
    return -1;
  }

  if(pos != end) {
    LOG_ERR("cms_decode_content_info - Not all data decoded!\n");
    return -1;
  }
#if EST_DEBUG_CMS
  LOG_DBG("cms_decode_content_info - All Data Decoded\n");
  hdump(pos-325, 325);

#endif

  /* If we are here then the message should be decoded */
  return 0;
}
/*----------------------------------------------------------------------------*/
int
cms_decode_signed_data(uint8_t **pos, uint8_t *end, cms_signed_data *cms)
{
  LOG_DBG("cms_decode_signed_data START\n");
  int res = 0;
  uint16_t length = 0;
  uint32_t CMSVersion = 0;

  /* Decode SignedData sequence */
  res = asn1_decode_tag(pos, end, &length, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));

  /* Decode version */
  res = cms_decode_version(pos, end, &CMSVersion);
  if((res < 0) || (cms_verify_version(CMSVersion) < 0)) {
    LOG_ERR("cms_decode_signed_data - could not verify version\n");
    return res;
  }

  LOG_DBG("cms_decode_signed_data - Signed Data Version Decoded\n");


  /* Decode digestAlgorithms constructed set SHOULD be empty e.g. with a length of zero */
  res = asn1_decode_tag(pos, end, &length, (ASN1_TAG_SET | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_ERR("WARNING: cms_decode_signed_data - could not decode digestAlgorithms\n");
  }
  if(length != 0) {
    LOG_ERR("WARNING: cms_decode_signed_data - digestAlgorithm not empty, try to continue\n");
    pos += length;
  }

  LOG_DBG("cms_decode_signed_data - Signed Data digestAlgorithms Decoded\n");


  /* Decode encapContentInfo constructed sequence */
  /* Decode and verify that OID is OID_ID_DATA */
  res = cms_decode_and_verify_encapContentInfo(pos, end, OID_ID_DATA);
  if(res < 0) {
    LOG_DBG("CMS ERROR: cms_decode_signed_data - could not decode encapContentInfo\n");
    return res;
  }
  LOG_DBG("cms_decode_signed_data - Signed Data encapContentInfo Decoded\n");


  /* Decode implicit tag 0 */
  /* Decode certificate chain */
  /* Skip over the implicit tag if it is there */
  res = asn1_decode_tag(pos, end, &length,
                        (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_WARN("WARNING: cms_decode_signed_data - Explicit tag missing, try to continue\n");
  }

  /* Update and initalize */
  uint8_t *certificates_end;
  certificates_end = *pos + length;

  /* Instead of end here we use pos + length so we know when we have reached
     the end of the list of certificates */
  res = x509_decode_certificate_sequence(pos, certificates_end, &cms->head);

  if((res < 0)) {
    LOG_ERR("cms_decode_signed_data - Could not decode certificates\n");
    return res;
  }

  LOG_DBG("cms_decode_signed_data - Signed Data certificates Decoded\n");


  /* Decode implicit tag 1, if it is not there => continue */
  /* Decode/SKIP CRLs SHOULD be 0*/
  if(**pos == (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x01)) {
    res = asn1_decode_tag(pos, end, &length, (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x01));
    if(res < 0) {
      LOG_ERR("cms_decode_signed_data - Could not decode crls\n");
      return res;
    }
    /* Skip over the crls field */
    (*pos) += length;
  }

  LOG_DBG("cms_decode_signed_data - Signed Data CRLs Decoded\n");


  /* Decode signerInfos, SHOULD be an empty constructed set if not empty ignore */
  res = asn1_decode_tag(pos, end, &length, (ASN1_TAG_SET | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_ERR("WARNING: cms_decode_signed_data - Could not decode signerInfos\n");
    res = 0;
    length = 0;
  }
  (*pos) += length;
  LOG_DBG("cms_decode_signed_data - Signed Data signerInfos Decoded\n");

  return 0;
}
/*----------------------------------------------------------------------------*/
int
cms_decode_version(uint8_t **pos, uint8_t *end, uint32_t *version)
{
  return asn1_decode_integer(pos, end, version);
}
/*----------------------------------------------------------------------------*/
int
cms_verify_version(uint32_t CMSVersion)
{
  int res = 0;

  /* Check if the version is a supported one */
  switch(CMSVersion) {
  case CMS_VERSION_0:
  case CMS_VERSION_1:
  case CMS_VERSION_2:
  case CMS_VERSION_3:
  case CMS_VERSION_4:
  case CMS_VERSION_5:
    break;
  default:
    LOG_DBG("CMS ERROR: cms_verify_version - Unsupported version %u\n", (int)CMSVersion);
    return -1;
  }

  return res;
}
/*----------------------------------------------------------------------------*/
int
cms_decode_and_verify_encapContentInfo(uint8_t **pos, uint8_t *end, char *str_oid)
{
  int res = 0;
  asn1_tlv content_type;
  uint16_t length = 0;

  uint16_t seq_len = 0;
  uint8_t *content_info_start;
  content_info_start = (*pos);

  /* Decode EncapsulatedContentInfo sequence */
  res = asn1_decode_tag(pos, end, &seq_len, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_DBG("CMS ERROR: cms_decode_and_verify_encapContentInfo - could not decode EncapsulatedContentInfo sequence\n");
    return res;
  }
#if EST_DEBUG_CMS
  LOG_DBG("cms_decode_and_verify_encapContentInfo - EncapsulatedContentInfo Sequence Decoded\n");
#endif
  seq_len += (*pos - content_info_start);   /* length of tag and length */

  /* Decode eContentType OID */
  content_type.tag = ASN1_TAG_OID;
  res = asn1_decode_tag(pos, end, &content_type.length, content_type.tag);
  if(res < 0) {
    LOG_DBG("CMS ERROR: cms_decode_and_verify_encapContentInfo - eContentType could not be decoded\n");
    return res;
  }
#if EST_DEBUG_CMS
  LOG_DBG("cms_decode_and_verify_encapContentInfo -  eContentType OID Decoded\n");
#endif

  /* Get the value and update position pointer */
  content_type.value = *pos;
  (*pos) += content_type.length;

  /* Check if it is the expected eContentType*/
  if(oid_cmp(str_oid, content_type.value, content_type.length) < 0) {
    LOG_DBG("CMS ERROR: cms_decode_and_verify_encapContentInfo - unsupported eContentType\n");
    return -1;
  }

  /* Check if we are at the end of the encapContentInfo*/
  if((*pos - content_info_start) == seq_len) {
    return 0;
  }

  /* Check for the eContent explicit [0] tag  */
  if(**pos == (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT)) {
    res = asn1_decode_tag(pos, end, &length, (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT));
    if(res < 0) {
      LOG_DBG("CMS ERROR: cms_decode_and_verify_encapContentInfo - Could not decode [0]\n");
      return res;
    }
#if EST_DEBUG_CMS
    LOG_DBG("cms_decode_and_verify_encapContentInfo - eContent explicit [0] tag Decoded\n");
#endif

    /* Skip over the eContent field because we don't support it */
    (*pos) += length;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
