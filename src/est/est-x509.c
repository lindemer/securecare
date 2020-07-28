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
 *          Implementations of the decode and encode for X.509 certificates
 *
 * \author
 *         Rúnar Már Magnússon  <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "est.h"
#include "est-x509.h"

#include "est-asn1.h"
#include "est-oid.h"

#include "../util/memb.h"
//#include "../other-ecc/bigint.h"
//#include "../other-ecc/other-ecc.h"

//#include <mbedtls/md.h> //mbetdtls_md_info_t
//#include "uip.h" /* For EUI-64 identifier */
//#include "net-debug.h" /* For PRINTLLADDR */
//#include "bigint.h"
#include "est-client.h" //settings
#include "mbedtls-wrapper.h" //crypto

#if EST_WITH_COFFEE
#include "cert-store.h"
#include "cert-store-client.h"
#endif

#include "../util/log.h"
#define LOG_MODULE "x509"
#ifdef LOG_CONF_LEVEL_EST_X509
#define LOG_LEVEL LOG_CONF_LEVEL_EST_X509
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif


/* Declare the memory section for x509 certificates */
MEMB(x509_sequnce_memb, x509_certificate, X509_MAX_STORED_CERTIFICATES);
static int current_certs = 0;

/* TODO: (Processing of X.509 Extensions) Process and validate X.509 extensions */

static x509_time current_time; //ctime is reserved in <time.h>
static unsigned long ctime_last_clocksec;

/*---------------------------------------------------------------------------*/
unsigned long clock_seconds(void) {
	struct timeval current_l_time;
	gettimeofday(&current_l_time, NULL);
	return current_l_time.tv_sec;
}
/*---------------------------------------------------------------------------*/
struct tm * x509_get_UTC(void) {
	struct timeval current_l_time;
	gettimeofday(&current_l_time, NULL);
	return gmtime(&current_l_time.tv_sec);
}
/*---------------------------------------------------------------------------*/
x509_time *
x509_get_ctime(void)
{
  unsigned long now = clock_seconds();
  unsigned long d = now - ctime_last_clocksec;
  uint8_t seconds = d % 60;
  uint8_t minutes = d / 60;
  uint8_t hours = d / 3600;
  int days = d / 3600*24;
  /* uint16_t year;    /\* 0000-9999 *\/ */
  /* uint8_t month;    /\* 1-12 *\/ */

  if (days > 31) {

    // TODO: handle months and years
  }

  current_time.second += seconds;
  if(current_time.second > 59) {
    current_time.second %= 60;
    current_time.minute++;
  }
  current_time.minute += minutes;
  if(current_time.minute > 59) {
    current_time.minute %= 60;
    current_time.hour++;
  }
  current_time.hour += hours;
  if(current_time.hour > 23) {
    current_time.hour %= 24;
    current_time.day++;
  }
  // TODO: handle day, month and years
  /* x509_print_ctime(); */
  ctime_last_clocksec = now;

  return &current_time;
}
/*---------------------------------------------------------------------------*/
void x509_print_ctime(void)
{
  printf("Current time: %hu-%02hu-%02hu %02hu:%02hu:%02hu\n",
         current_time.year, current_time.month, current_time.day,
         current_time.hour, current_time.minute, current_time.second);
}
/*---------------------------------------------------------------------------*/
void x509_set_ctime(char *str)
{
  if(str) {
    /* Splitting string e.g. 2017-04-20T11:45:10.549Z */
    char *yyyy = strtok(str, "-");
    char *MM = strtok(NULL, "-");
    char *dd = strtok(NULL, "T");
    char *hh = strtok(NULL, ":");
    char *mm = strtok(NULL, ":");
    char *ss = strtok(NULL, ".");

    current_time.year = atoi(yyyy);
    current_time.month = atoi(MM);
    current_time.day = atoi(dd);
    current_time.hour = atoi(hh);
    current_time.minute = atoi(mm);
    current_time.second = atoi(ss);
  }  else {
      struct tm * cur_time = x509_get_UTC();
      current_time.year = 1900 + cur_time->tm_year; //UTC = years since 1900
      current_time.month = 1 + cur_time->tm_mon;	//UTC = month since January
      current_time.day = cur_time->tm_mday;
      current_time.hour = cur_time->tm_hour;
      current_time.minute = cur_time->tm_min;
      current_time.second = cur_time->tm_sec;

  }
//  else {
//    /* HACK Set current time to be a month after compile time for passing cert validity checking */
//    static const char mons[] = {"JanFebMarAprMayJunJulAugSepOctNovDec"};
//
//    // DATE and TIME strings from GCC preprocesser: e.g. Mar 23 2017 15:17:18
//    printf("Setting current time based on compile time: %s %s\n", __DATE__, __TIME__);
//
//    ctime.year = (uint16_t)atoi(&__DATE__[7]);    /* 0000-9999 */
//    char mon[4];
//    (void)strncpy(mon, &__DATE__[0], sizeof(mon));
//    mon[3] = '\0';
//    ctime.month = (uint8_t)((strstr(mons, mon) - (char *)mons) / 3); /* 0-11 */
//    ctime.month = (ctime.month + 1) % 12 + 1; /* 1-12 */
//    if(1 == ctime.month) {
//      ctime.year++;
//    }
//    ctime.day = (uint8_t)atoi(&__DATE__[4]);      /* 1-31 */
//
//    ctime.hour = (uint8_t)atoi(&__TIME__[0]);     /* 0-23 */
//    ctime.minute = (uint8_t)atoi(&__TIME__[3]);   /* 0-59 */
//    ctime.second = (uint8_t)atoi(&__TIME__[6]);   /* 0-59 */
//
//  }
  
  current_time.format = UTC_TIME_Z;
  current_time.sign = 0;      /* Used in utcTIME: -1, 0 (sign not used), +1 */
  current_time.diff_hour = 0;
  current_time.diff_minute = 0;
  ctime_last_clocksec = clock_seconds();
  
}
/*----------------------------------------------------------------------------*/
void
x509_print_certificate(x509_certificate *cert)
{
  if(cert != NULL) {

    /* Print Certificate information */
    /* LOG_DBG("---- Certificate ----\n"); */
    /* LOG_DBG("Address: %p \n", cert); */
    // XXX disable debug print
    /* asn1_print(&cert->cert_tlv); */
    /* LOG_DBG("Version: %u\n", cert->version); */
    printf("Serial: ");
    asn1_print(&cert->serial_number);
//    int j = 0;
//    for(j = 0; j < (&cert->serial_number)->length; j++) {
//	    printf("%02X ", (&cert->serial_number)->value[j]);
//    }
    printf("\n");
    /* LOG_DBG("Signature: \n"); */
    /* LOG_DBG(" - algorithm: "); */
    /* asn1_print(&cert->signature_algorithm_ID.algorithm_oid); */
    /* LOG_DBG(" - params:    "); */
    /* asn1_print(&cert->signature_algorithm_ID.parameters); */
    /* LOG_DBG("Issuer: \n"); */
    /* asn1_print(&cert->issuer_name); */
    printf("Validity: \n");
    printf(" - Not Before: ");
    x509_print_time(&cert->validity.not_before);
    printf(" - Not After:  ");
    x509_print_time(&cert->validity.not_after);
    printf("\n");
    /* LOG_DBG("Subject: "); */
    /* asn1_print(&cert->subject_name); */
    printf("Subject Public Key Info: \n");
    printf(" - Algorithm Identifier\n");
    printf(" - - algorithm: ");
    asn1_print(&cert->pk_info.public_key_algorithm.algorithm_oid);
    printf(" - - params:    ");
    asn1_print(&cert->pk_info.public_key_algorithm.parameters);
    printf(" - subjectPublicKey: ");
    asn1_print_bit_string(&cert->pk_info.subject_public_key);

    /* LOG_DBG("issuer_unique_ID:  "); */
    /* asn1_print_bit_string(&cert->issuer_unique_ID); */
    /* LOG_DBG("subject_unique_ID: "); */
    /* asn1_print_bit_string(&cert->subject_unique_ID); */
    /* LOG_DBG("extensions: "); */
    /* asn1_print(&cert->extensions); */

    /* Print Signature Algorithm Identifier */
    /* LOG_DBG("---- Signature Algorithm ----\n"); */
    /* LOG_DBG("TBScertificate - Data start: %p, Data length: %d, Signature start: %p, Signature length: %d\n", */
    /*          &cert->tbs_cert_start, cert->tbs_cert_len, &cert->sign_start, cert->sign_len); */
    /* LOG_DBG(" - algorithm: "); */
    /* asn1_print(&cert->certificate_signature_algorithm.algorithm_oid); */
    /* LOG_DBG(" - params:    "); */
    /* asn1_print(&cert->certificate_signature_algorithm.parameters); */

   /* Print signature */
    /* LOG_DBG("---- Signature ----\n"); */
    /* asn1_print_bit_string(&cert->certificate_signature); */
  } else {
    printf(" Certificates is NULL\n");
  }
}
/*----------------------------------------------------------------------------*/
void
x509_print_certificate_chain(x509_certificate *cert)
{
  x509_certificate *tmp = NULL;
  tmp = cert;
  int i = 1;
  if(tmp == NULL) {
    LOG_DBG("The certificate does not have a valid reference\n");
  }
  while(tmp != NULL) {
    LOG_DBG("<---- Certificate %d ---->\n", i);
    i = i + 1;
    x509_print_certificate(tmp);
    tmp = tmp->next;
  }
}
/*----------------------------------------------------------------------------*/
void
x509_print_time(x509_time *time)
{
  printf("Format: %d, Year: %d, Month: %d, Day: %d, Hour: %d, Minute: %d, Second: %d",
           time->format, time->year, time->month, time->day, time->hour, time->minute, time->second);

  if(time->sign == 1) {
    LOG_DBG(" Diff: +, Hour: %d, Minute: %d",
             time->diff_hour, time->diff_minute);
  } else if(time->sign == -1) {
    LOG_DBG(" Diff: -, Hour: %d, Minute: %d",
             time->diff_hour, time->diff_minute);
  }
  printf("\n");
}
/*----------------------------------------------------------------------------*/
void
x509_memb_init()
{
  memb_init(&x509_sequnce_memb);
}
/*----------------------------------------------------------------------------*/
void
x509_init_certificate(x509_certificate *cert)
{
  LOG_DBG("initializing certificate\n");
  memset(cert, 0, sizeof(x509_certificate));
  cert->next = NULL;
}
/*----------------------------------------------------------------------------*/
x509_certificate *
x509_memb_create_certificate()
{
  x509_certificate *cert = NULL;

  cert = memb_alloc(&x509_sequnce_memb);
  if(cert == NULL) {
    LOG_DBG("Could not allocate memory for certificate, current_certs = %d\n", current_certs);
  } else {
    current_certs++;
    LOG_DBG("value of current_certs = %d\n", current_certs);
    x509_init_certificate(cert);
  }

  return cert;
}
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
int
x509_memb_remove_certificates(x509_certificate *cert)
{
  x509_certificate *tmp = NULL;
  int res = 0;

  while(cert != NULL) {
    tmp = cert->next;
    if(memb_free(&x509_sequnce_memb, cert) < 0) {
      LOG_ERR("X.509 ERROR - x509_memb_remove_certificates: Could not remove certificate\n");
      res = -1;
    }
    cert = tmp;
  }
#if EST_DEBUG_X509
  //LOG_DBG("x509_memb_remove_certificates - Certificate removed\n");
  current_certs--;
  LOG_DBG("x509_memb_remove_certificates - Certificate removed, current_certs = %d\n", current_certs);
#endif
  return res;
}
/*----------------------------------------------------------------------------*/
int
x509_set_eui64_subject(asn1_tlv *subject, uint8_t *value, uint16_t value_length)
{
  uint8_t *pos;
  uint16_t length = 0;
  int res = 0;
  pos = value + value_length;
  memset(value, 0, value_length);

#if EST_DEBUG_X509
  LOG_DBG("x509_set_eui64_subject - MY client_mac_id: ");
  //PRINTLLADDR(&uip_lladdr);
  LOG_DBG("\n");
#endif

  int i = 0;
  if(value_length < X509_EUI64_SUBJECT_SIZE) {
    LOG_ERR("X.509 ERROR - x509_set_eui64_subject: buffer length %u smaller than %u\n",
             value_length, X509_EUI64_SUBJECT_SIZE);
    return -1;
  }

  /* Encode the EUI-64 as a string and set it as a common name */
  pos -= (3 * UIP_802154_LONGADDR_LEN) - 1;

  /* Write the MAC address as a UTF-8 string */
  char *s;
  s = (char *)pos;
  for(i = 0; i < UIP_802154_LONGADDR_LEN; i++) {
    if(i > 0) {
      sprintf(s, X509_EUI64_DELIM);
      s += 1;
    }
    //sprintf(s, "%02X", uip_lladdr.addr[i]);
    sprintf(s, "%02X", client_mac_id[i]);
    s += 2;
  }
  length += 3 * UIP_802154_LONGADDR_LEN - 1;

  /* Encode the UTF-8 length and tag */
  res = asn1_encode_length_and_tag(&pos, value, ASN1_TAG_PRINTABLE_STRING, length);
  if(res < 0) {
    return res;
  }
  length += res;

  /* Encode the Common Name OID */
  uint8_t cn_oid[] = OID_ID_AT_COMMON_NAME;
  res = asn1_encode_oid(&pos, value, cn_oid, OID_LENGTH(OID_ID_AT_COMMON_NAME));
  if(res < 0) {
    return res;
  }
  length += res;

  /* Encode the sequence the common name OID and the common name */
  res = asn1_encode_length_and_tag(&pos, value,
                                   (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT), length);
  if(res < 0) {
    return res;
  }
  length += res;

  /* Encode the set containing the common name */
  res = asn1_encode_length_and_tag(&pos, value,
                                   (ASN1_TAG_SET | ASN1_P_C_BIT), length);
  if(res < 0) {
    return res;
  }
  length += res;

  /* Set the value, tag and length of the subject */
  subject->value = value;
  subject->length = length;
  subject->tag = (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT);

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_algorithm_identifier(uint8_t **pos, uint8_t *end, asn1_tlv *alg_oid, asn1_tlv *params)
{
  int res = 0;
  uint16_t length = 0;
  uint8_t *alg_end;

  /* Decode the AlgorithmIdentifier Constructed sequence */
  res = asn1_decode_tag(pos, end, &length, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
  if(res < 0) {
    return res;
  }
  /* Set the end pointer */
  alg_end = (*pos) + length;
  if(alg_end > end) {
    LOG_ERR("X.509 ERROR - x509_decode_algorithm_identifier: Length malformed \n");
    return -1;
  }

  alg_oid->tag = ASN1_TAG_OID;
  /* Decode OID */
  res = asn1_decode_tag(pos, end, &alg_oid->length, alg_oid->tag);
  if(res < 0) {
    return res;
  }
  /* Update pointers */
  alg_oid->value = (*pos);
  (*pos) += alg_oid->length;

  /* Check if there is any optional parameters */
  if(*pos < alg_end) {
    params->tag = **pos;

    res = asn1_decode_tag(pos, end, &params->length, params->tag);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_decode_algorithm_identifier: Could not decode optional parameters\n");
      return res;
    }
    /* Update pointers */
    params->value = (*pos);
    (*pos) += params->length;
  }

  if(*pos != alg_end) {
    LOG_ERR("X.509 ERROR - x509_decode_algorithm_identifier: algorithm identifier end not aligned\n");
    return -1;
  }
#if EST_DEBUG_X509
  LOG_DBG("x509_decode_algorithm_identifier - Algorithm Identifier Decoded \n");
#endif

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_encode_algorithm_identifier(uint8_t **pos, uint8_t *start, asn1_tlv *alg_oid, asn1_tlv *params)
{
  int res = 0;
  uint16_t length = 0;

  /* If no params are specified e.g. for signature algorithm identifiers then we do nothing*/
  if((params != NULL) && (params->value != NULL)) {
    /* Assume that the parameters are all in the value buffer */
    res = asn1_encode_buffer(pos, start, params->value, params->length);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_encode_algorithm_identifier: Could not encode parameters value\n");
      return res;
    } else {
      length += res;
    }
    /* Encode the tag and value of the params*/
    res = asn1_encode_length_and_tag(pos, start, params->tag, params->length);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_encode_algorithm_identifier: Could not encode parameters\n");
      return res;
    } else {
      length += res;
    }
  }

  /* Encode the algorithm OID */
  res = asn1_encode_oid(pos, start, alg_oid->value, alg_oid->length);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_encode_algorithm_identifier: Could not encode algorithm OID\n");
    return res;
  } else {
    length += res;
  }

  /* Encode the AlgorithmIdentifier */
  res = asn1_encode_length_and_tag(pos, start,
                                   (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT),
                                   length);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_encode_algorithm_identifier: Could not encode AlgorithmIdentifier Sequence tag\n");
    return res;
  } else {
    length += res;
  }

  return length;
}
/*----------------------------------------------------------------------------*/
/* Internal method to encode an EC public key as a bit-string */
int
x509_encode_EC_public_key_as_bit_string(uint8_t **pos, uint8_t *start, uint8_t *pub_x, uint8_t *pub_y, uint16_t key_len)
{
  int res = 0;
  uint16_t length = 0;

  res = asn1_encode_buffer(pos, start, pub_y, key_len);
  if(res < 0) {
    LOG_ERR("x509_encode_EC_public_key_as_bit_string: Could not encode Pub.y\n");
    return res;
  } else {
    length += res;
  }

  res = asn1_encode_buffer(pos, start, pub_x, key_len);
  if(res < 0) {
    LOG_ERR("x509_encode_EC_public_key_as_bit_string: Could not encode Pub.x\n");
    return res;
  } else {
    length += res;
  }

  /* We only support uncompressed format RFC 5480*/
  *--(*pos) = (uint8_t)ECC_POINT_UNCOMPRESSED;
  length += 1;

  /* No unused bits in the bit-string so the initial byte is 0x00 */
  *--(*pos) = (uint8_t)0x00;
  length += 1;

  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_BIT_STRING, length);
  if(res < 0) {
    LOG_ERR("x509_encode_EC_public_key_as_bit_string: Could not bitstring tag\n");
    return res;
  } else {
    length += res;
  }

  return length;
}
/*----------------------------------------------------------------------------*/
int
x509_encode_pk_info(uint8_t **pos, uint8_t *start, x509_key_context *pk_ctx)
{
  asn1_tlv alg_oid;
  asn1_tlv alg_params;
  uint16_t key_len = 0;

  int res = 0;
  uint16_t length = 0;

  /* Set the public key type */
  switch(pk_ctx->pk_alg) {
  case ECC_PUBLIC_KEY:
    alg_oid.tag = ASN1_TAG_OID;
    alg_oid.value = (uint8_t *)OID_ID_EC_PUBLIC_KEY;
    alg_oid.length = OID_LENGTH(OID_ID_EC_PUBLIC_KEY);
    break;
  default:
    LOG_ERR("X.509 ERROR: x509_encode_pk_info - Unknown Algorithm\n");
    return -1;
  }

  /* Set the parameters for the algorithm identifier */
  switch(pk_ctx->curve) {
  case SECP256R1_CURVE:
    alg_params.tag = ASN1_TAG_OID;
    alg_params.value = (uint8_t *)OID_CURVE_NAME_SECP256R1;
    alg_params.length = OID_LENGTH(OID_CURVE_NAME_SECP256R1);
    key_len = ECC_DEFAULT_KEY_LEN;         /* TODO: Use a predefined variable */
    break;
  default:
    LOG_ERR("X.509 ERROR: x509_encode_pk_info - Unknown Curve\n");
    return -1;
  }

  /* Encode the subjectPublicKey */
  res = x509_encode_EC_public_key_as_bit_string(pos, start,
                                                pk_ctx->pub_x, pk_ctx->pub_y, key_len);
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_encode_pk_info - Could not encode public key\n");
    return res;
  } else {
    length += res;
  }

  /* Encode the algorithm */
  res = x509_encode_algorithm_identifier(pos, start, &alg_oid, &alg_params);
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_encode_pk_info - Could not encode algorithm identifier\n");
    return res;
  } else {
    length += res;
  }

  /* Encode the SubjectPublicKeyInfo */
  res = asn1_encode_length_and_tag(pos, start,
                                   (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT),
                                   length);
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_encode_pk_info - Could not encode the SubjectPublicKeyInfo sequence\n");
    return res;
  } else {
    length += res;
  }

  return length;
}
/*----------------------------------------------------------------------------*/
int
x509_encode_signature(uint8_t **sign_pos, uint8_t *sign_start, uint8_t *buffer,
                      uint16_t buf_len, x509_key_context *pk_ctx)
{
  int res = 0;
  uint16_t length = 0;

  /* Create the signature based on the key context */
  switch(pk_ctx->sign) {

  case ECDSA_WITH_SHA256:
    switch(pk_ctx->curve) {
    case SECP256R1_CURVE:
      res = x509_encode_ecdsa_signature(sign_pos, sign_start, buffer,
                                        buf_len, pk_ctx->priv, SECP256R1_KEY_LEN_WORDS);
      break;
    default:
      LOG_ERR("X.509 ERROR - x509_encode_signature: Unknown curve\n");
      return -1;
    }
    break;

  default:
    LOG_ERR("X.509 ERROR - x509_encode_signature: Unknown signature algorithm\n");
    return -1;
  }

  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_encode_signature: Could not encode signature\n");
    return res;
  }
  length += res;

  return length;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_signature(uint8_t *buffer, uint16_t buf_len, uint8_t *sign_start,
                      uint16_t sign_len, x509_key_context *pk_ctx)
{
  int res = 0;

  switch(pk_ctx->sign) {

  case ECDSA_WITH_SHA256:
    switch(pk_ctx->curve) {
    case SECP256R1_CURVE:
      res = x509_verify_ecdsa_signature(buffer, buf_len, sign_start,
                                        sign_len, SECP256R1_KEY_LEN_WORDS, pk_ctx);
      break;
    default:
      LOG_ERR("X.509 ERROR - x509_verify_signature: Unknown curve\n");
      return -1;
    }
    break;

  default:
    LOG_ERR("X.509 ERROR - x509_verify_signature: Unknown signature algorithm\n");
    return -1;
  }

  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_verify_signature: Could not verify signature\n");
    return res;
  }

  return res;
}
/*----------------------------------------------------------------------------*/
int
x509_encode_signature_component(uint8_t **sign_pos, uint8_t *sign_start,
		uint8_t *component, size_t component_len)
{
  int res = 0;
  uint16_t length = 0;
  int num_words = 8;

  /* Encode the signature components r and s as integers */
  (*sign_pos) -= (num_words * WORD_LEN_BYTES);
  memcpy(*sign_pos, component, component_len);
  length += (num_words * WORD_LEN_BYTES);

  /* We need to put 0x00 in front of integers if the sign bit is set */
  if((**sign_pos & 0x80)) {
    *--(*sign_pos) = 0x00;
    length += 1;
    res = asn1_encode_length_and_tag(sign_pos, sign_start, ASN1_TAG_INTEGER,
                                     ((num_words * WORD_LEN_BYTES) + 1));
  } else {
    res = asn1_encode_length_and_tag(sign_pos, sign_start, ASN1_TAG_INTEGER,
                                     ((num_words * WORD_LEN_BYTES)));
  }
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_encode_signature_component: Could not encode signature component\n");
    return res;
  }
  /* Set the final length */
  length += res;

  return length;
}
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
int
x509_encode_ecdsa_signature(uint8_t **sign_pos, uint8_t *sign_start,
                            uint8_t *buffer, uint16_t buf_len, uint8_t *private_key, uint16_t num_words)
{
  int res = 0;
  uint16_t data_length;
  uint16_t length = 0;
  data_length = buf_len;

  /* Initialize buffers for the signature and private key */

#ifdef COSE_BACKEND_NRF

    RETURN_ERROR(nrf_crypto_ecdsa_sign(NULL, &ctx->ctx.priv, ctx->hash.hash,
                ctx->hash.len, ctx->sig, &ctx->len_sig));

#elif NOT_TRUE_YET

    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_ecdsa_context * ecdsa = ctx->ctx.pk_ctx;
    RETURN_ERROR(mbedtls_ecdsa_sign_det(&ecdsa->grp, &r, &s, &ecdsa->d,
                ctx->hash.hash, ctx->hash.len, ctx->hash.type));
    RETURN_ERROR(mbedtls_mpi_write_binary(&r, ctx->sig, COSE_P256_KEY_LENGTH));
    RETURN_ERROR(mbedtls_mpi_write_binary(&s, ctx->sig + COSE_P256_KEY_LENGTH,
            COSE_P256_KEY_LENGTH));

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    ctx->len_sig = COSE_P256_KEY_LENGTH * 2;

#endif


  /* Generate the signature */

  unsigned char r_buf[ECC_DEFAULT_KEY_LEN];
  unsigned char s_buf[ECC_DEFAULT_KEY_LEN];
  res = create_ecc_signature(buffer, data_length, r_buf, ECC_DEFAULT_KEY_LEN, s_buf, ECC_DEFAULT_KEY_LEN);

  if(0 < res) {
    /* Encode the signature components r and s as integers */

    /* Encode the s signature component */
	res = x509_encode_signature_component(sign_pos, sign_start, s_buf, ECC_DEFAULT_KEY_LEN);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_encode_ecdsa_signature: Could not encode the s integer tag\n");
      return res;
    } else {
      length += res;
    }

    /* Encode the r signature component */
    res = x509_encode_signature_component(sign_pos, sign_start, r_buf, ECC_DEFAULT_KEY_LEN);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_encode_ecdsa_signature: Could not encode the r integer tag\n");
      return res;
    } else {
      length += res;
    }

    /* Encode the Ecdsa-Sig-Value Sequence */
    res = asn1_encode_length_and_tag(sign_pos, sign_start,
                                     (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT),
                                     length);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_encode_ecdsa_signature: Could not encode the Ecdsa-Sig-Value tag\n");
      return res;
    } else {
      length += res;
    }

    /* Encode the signature bit-string */
    /* No unused bits in the bit-string so the initial byte is 0x00 */
    *--(*sign_pos) = (uint8_t)0x00;
    length += 1;

    /* Encode the signature bit-string */
    res = asn1_encode_length_and_tag(sign_pos, sign_start, ASN1_TAG_BIT_STRING, length);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_encode_ecdsa_signature: Could not encode signature bit-string\n");
      return res;
    } else {
      length += res;
    }

    return length;
  }

  LOG_ERR("X.509 ERROR - x509_encode_ecdsa_signature: Could not generate signature\n");
  return -1;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_signature_component(uint8_t **sign_pos, uint8_t *sign_end,
                                uint16_t num_words, asn1_tlv *component_tlv) //u_word *component)
{
  int res = 0;
  //asn1_tlv component_tlv;

  component_tlv->tag = ASN1_TAG_INTEGER;

  /* */
  res = asn1_decode_tag(sign_pos, sign_end, &component_tlv->length, component_tlv->tag);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_signature_component: Could not decode the signature component\n");
    return res;
  }

  if(component_tlv->length == ((num_words * WORD_LEN_BYTES) + 1)) {
    component_tlv->value = (*sign_pos) + 1;
    (*sign_pos) += component_tlv->length;
    component_tlv->length -= 1;
  } else {
    component_tlv->value = (*sign_pos);
    (*sign_pos) += component_tlv->length;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_ecdsa_signature(uint8_t *buffer, uint16_t buf_len, uint8_t *sign_start,
                            uint16_t sign_len, uint8_t num_words, x509_key_context *pk_ctx)
{
  int res = 0;
  uint16_t length = 0;

  /* The length of the data that is signed */
  uint16_t data_len = buf_len;
  uint8_t *sequence_pos;
  uint8_t *sign_pos = sign_start;
  uint8_t *end = sign_start + sign_len;

  /* ASN.1 objects */
  asn1_bitstring signature;


  /* Decode bit-string */
  res = asn1_decode_bit_string(&sign_pos, end, &signature);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_verify_ecdsa_signature: Could not decode signature bit-string\n");
    return res;
  }
  /* Check if the bit-string */
  if((signature.zero_bits != 0)) {
    LOG_ERR("X.509 ERROR - x509_verify_ecdsa_signature: The signature contains unused bits\n");
    return -1;
  }

  /* Update the pointer to the sequence inside the bit-string */
  sequence_pos = signature.bit_string;

  /* Decode sequence tag and verify that the signature contains two
     ASN.1 integers of length (key_len) bytes*/
  res = asn1_decode_tag(&sequence_pos, end, &length, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
  if((res < 0) || (length < (2 * num_words * WORD_LEN_BYTES + 4))) {
    LOG_ERR("X.509 ERROR - x509_verify_ecdsa_signature: Malformed ecdsa-sig-value sequence\n");
    return res;
  }

  /* Decode r signature component */

  asn1_tlv r_component_tlv;
  res = x509_decode_signature_component(&sequence_pos, end, num_words, &r_component_tlv);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_verify_ecdsa_signature: Could not decode the r component\n");
    return res;
  }

  /* Decode s signature component*/
  asn1_tlv s_component_tlv;
  res = x509_decode_signature_component(&sequence_pos, end, num_words, &s_component_tlv);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_verify_ecdsa_signature: Could not decode the s component\n");
    return res;
  }
//  bigint_decode(s, num_words, s_component_tlv.value, s_component_tlv.length);
  //store-r-s(component_tlv.value)

  if(sequence_pos != end) {
    LOG_ERR("X.509 ERROR - x509_verify_ecdsa_signature: Signature not aligned with end of buffer\n");
    return -1;
  }

  /* Verify the signature */

#if 0 < WITH_COMPRESSION && EST_DEBUG_X509
  LOG_DBG("Content of buffer to check:\n");
  hdumps(buffer, data_len);
#endif

	int st = verify_ecc_signature(pk_ctx, buffer, data_len, r_component_tlv.value, r_component_tlv.length, s_component_tlv.value, s_component_tlv.length);
	if (st < 0) {
		LOG_ERR("X.509 ERROR - x509_verify_ecdsa_signature: The ECDSA signature could not be verified\n");
		return -1;
	}

	LOG_DBG("x509_verify_ecdsa_signature: ECDSA signature verified\n");

  /* The signature is valid */
  return 0;

}

/*----------------------------------------------------------------------------*/
uint16_t
x509_signature_bit_string_length(x509_key_context *pk_ctx)
{
  uint16_t length = 0;

  switch(pk_ctx->sign) {
  case ECDSA_WITH_SHA256:
    length += 2 * 32;       /* TODO: find SHA_256 hash length defined */
    length += 11;          /* ASN.1 tags and lengths */
    break;
  default:
    break;
  }

  return length;
}
/*----------------------------------------------------------------------------*/
int
x509_encode_subject(uint8_t **pos, uint8_t *start, asn1_tlv *name)
{
  /* TODO: Make it easier to encode a sequence of sets for subject */
  uint16_t length = 0;
  int res = 0;

  /* Encode the sets */
  res = asn1_encode_buffer(pos, start, name->value, name->length);
  if(res < 0) {
    return res;
  } else {
    length += res;
  }

  /* Encode the subjectName sequence */
  res = asn1_encode_length_and_tag(pos, start, name->tag, name->length);
  if(res < 0) {
    return res;
  } else {
    length += res;
  }

  return length;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_certificate_sequence(uint8_t **pos, uint8_t *end, x509_certificate **head)
{
  int res = 0;
  uint16_t length = 0;
  uint8_t *cert_end;
  uint8_t *cert_pos;
  x509_certificate *tmp;
  x509_certificate *chain_pos;
  tmp = NULL;
  chain_pos = NULL;
  *head = tmp;

  /* Set of certificateChoices */
  while((*pos < end) && (res >= 0)) {

    cert_pos = (*pos);
    res = asn1_decode_tag(pos, end, &length, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
    if(res < 0) {
      return res;
    }
    cert_end = (*pos) + length;

    /* Only a single certificate */
    tmp = x509_decode_certificate(&cert_pos, cert_end);

    if(tmp == NULL) {
      LOG_ERR("x509_decode_certificate_sequence: Could not decode certificate\n");
      /* Remove the certificates */
      x509_memb_remove_certificates((*head));
      return -1;
    }
    (*pos) += length;

    /* Update pointer in the chain TODO test for more than one */
    if((*pos) <= end) {
      if(*head == NULL) {
        *head = tmp;
        (*head)->next = NULL;
      } else {
        /* Find the tail of the linked list */
        chain_pos = *head;
        while(chain_pos->next != NULL) {
          chain_pos = chain_pos->next;
        }
        chain_pos->next = tmp;
        chain_pos->next->next = NULL;
      }
    }
  }
#if EST_DEBUG_X509
  LOG_DBG("x509_decode_certificate_sequence - Certificate sequence decoded\n");
#endif
  return 0;
}
/*----------------------------------------------------------------------------*/
x509_certificate *
x509_decode_certificate(uint8_t **pos, uint8_t *end)
{
  x509_certificate *cert = NULL;
  int res = 0;

  /* Allocate memory for certificate */
  cert = x509_memb_create_certificate();

#if EST_DEBUG_X509
  LOG_DBG("x509_decode_certificate -Certificate start: %p, end: %p, length: %d, X.509 Cert %p \n", pos, end, (int)(end - (*pos)), cert);
#if 0 < WITH_COMPRESSION
  hdump(*pos, (int)(end - (*pos)));
#endif
#endif

  /* Set the tag of the Certificate sequence */
  cert->cert_tlv.tag = (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT);
  res = asn1_decode_tag(pos, end, &cert->cert_tlv.length, cert->cert_tlv.tag);
  cert->cert_tlv.value = (*pos);

  /* Set the start of the data that is signed signature */
  cert->tbs_cert_start = (*pos);

  /* Decode tbsCertificate */
  res = x509_decode_tbs_certificate(pos, end, cert);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_certificate: Could not decode certificate\n");
    x509_memb_remove_certificates(cert);
    return NULL;
  }

  /* Calculate the length of the data that was signed */
  cert->tbs_cert_len = (uint16_t)((*pos) - cert->tbs_cert_start);

  /* Decode signature Algorithm */
  res = x509_decode_algorithm_identifier(pos, end,
                                         &cert->certificate_signature_algorithm.algorithm_oid,
                                         &cert->certificate_signature_algorithm.parameters);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_certificate: Could not decode algorithm identifier\n");
    x509_memb_remove_certificates(cert);
    return NULL;
  }

  /* Decode signature */
  cert->sign_start = (*pos);
  res = x509_decode_signature(pos, end, &cert->certificate_signature);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_certificate: Could not decode signature\n");
    x509_memb_remove_certificates(cert);
    return NULL;
  }
  /* Set the pointer to the end of the signature */
  cert->sign_len = (uint16_t)((*pos) - cert->sign_start);

  return cert;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_tbs_certificate(uint8_t **pos, uint8_t *end, x509_certificate *cert)
{
  int res = 0;
  uint16_t length = 0;
  uint16_t cert_len = 0;

  /* Decode TBSCertificate constructed sequence */
  res = asn1_decode_tag(pos, end, &cert_len, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode TBSCertificate sequence\n");
    return res;
  }

  /* Decode version [0] */
  res = x509_decode_version(pos, end, &cert->version);
  if(res < 0) {
    /* Some test data has no version so we try to skip it */
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode version\n");
  }

  /* Decode serial Number */
  cert->serial_number.tag = ASN1_TAG_INTEGER;
  res = asn1_decode_tag(pos, end, &cert->serial_number.length, cert->serial_number.tag);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode serial\n");
    return res;
  }

  /* Update pointer */
  cert->serial_number.value = (*pos);
  (*pos) += cert->serial_number.length;

  /* Decode signature AlgorithmIden */
  res = x509_decode_algorithm_identifier(pos, end,
                                         &cert->signature_algorithm_ID.algorithm_oid,
                                         &cert->signature_algorithm_ID.parameters);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode signature algorithm identifier\n");
    return res;
  }

  /* Decode Issuer */
  res = x509_decode_issuer(pos, end, &cert->issuer_name);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode issuer\n");
    return res;
  }

  /* Decode Validity */
  res = x509_decode_validity(pos, end, &cert->validity);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode validity\n");
    return res;
  }

  /* Decode Subject */
  res = x509_decode_subject(pos, end, &cert->subject_name);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode subject\n");
    return res;
  }

  /* Decode subjectPublicKeyInfo */
  res = x509_decode_pk_info(pos, end, &cert->pk_info);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode subjectPublicKeyInfo\n");
    return res;
  }

  /* Decode optional tags */
  /* Decode issuerUniqueID [1] Implicit */
  if(**pos == (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x01)) {
    res = asn1_decode_tag(pos, end, &length,
                          (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x01));
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode [1]\n");
      return res;
    }

    /* Decode the bit-string */
    res = asn1_decode_bit_string(pos, (*pos) + length, &cert->issuer_unique_ID);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode issuerUniqueID\n");
      return res;
    }
  }

  /* Decode subjectUniqueID [2] Implicit */
  if(**pos == (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x02)) {
    res = asn1_decode_tag(pos, end, &length,
                          (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x02));
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode [2]\n");
      return res;
    }

    /* Decode the bit-string */
    res = asn1_decode_bit_string(pos, (*pos) + length, &cert->subject_unique_ID);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode subjectUniqueID\n");
      return res;
    }
  }

  /* Decode extensions [3] */
  if(**pos == (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x03)) {
    res = asn1_decode_tag(pos, end, &length,
                          (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT | 0x03));
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode [3]\n");
      return res;
    }

    /* Decode the Extensions sequence */
    cert->extensions.tag = (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT);
    res = asn1_decode_tag(pos, (*pos) + length,
                          &cert->extensions.length, cert->extensions.tag);
    if(res < 0) {
      LOG_ERR("X.509 ERROR - x509_decode_tbs_certificate: Could not decode extensions sequence\n");
      return res;
    }

    /* Update pointers */
    cert->extensions.value = (*pos);
    (*pos) += cert->extensions.length;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_pk_info(uint8_t **pos, uint8_t *end, x509_subject_pk_info *pk_info)
{
  int res = 0;
  uint16_t length = 0;
  uint8_t *pk_end;

  /* Decode subjectPublicKeyInfo constructed sequence */
  res = asn1_decode_tag(pos, end, &length, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_pk_info: Could not decode subjectPublicKeyInfo sequence\n");
    return res;
  }
  /* Set a pointer that points to the end of the subjectPublicKeyInfo */
  pk_end = (*pos) + length;

  /* Decode algorithm identifier */
  res = x509_decode_algorithm_identifier(pos, end,
                                         &pk_info->public_key_algorithm.algorithm_oid,
                                         &pk_info->public_key_algorithm.parameters);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_pk_info: Could not decode algorithm identifier\n");
    return res;
  }

  /* Decode public key bit-string */
  res = asn1_decode_bit_string(pos, pk_end, &pk_info->subject_public_key);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_pk_info: Could not decode pub-key bit-string\n");
    return res;
  }

  /* Perform validation of the public key */
  res = x509_verify_public_key(&pk_info->public_key_algorithm.algorithm_oid,
                               &pk_info->public_key_algorithm.parameters, &pk_info->subject_public_key);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_pk_info: Malformed public key\n");
    return res;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_pk_info_to_pk_ctx(x509_subject_pk_info *pk_info, x509_key_context *pk_ctx)
{
  int res = 0;
  uint16_t key_length = 0;

  /* Set the public key algorithm  */
  if(oid_cmp(OID_ID_EC_PUBLIC_KEY,
             pk_info->public_key_algorithm.algorithm_oid.value,
             pk_info->public_key_algorithm.algorithm_oid.length) == 0) {
    pk_ctx->pk_alg = ECC_PUBLIC_KEY;
  } else {
    LOG_ERR("X.509 ERROR - x509_pk_info_to_pk_ctx: Unsupported public-key algorithm \n");
    return -1;
  }

  /* Set the curve */
  uint8_t *pub_x_pos;
  uint8_t *pub_y_pos;

  if(oid_cmp(OID_CURVE_NAME_SECP256R1,
             pk_info->public_key_algorithm.parameters.value,
             pk_info->public_key_algorithm.parameters.length) == 0) {
    pk_ctx->curve = SECP256R1_CURVE;
    key_length = ECC_DEFAULT_KEY_LEN;
  } else {
    LOG_ERR("X.509 ERROR - x509_pk_info_to_pk_ctx: Unsupported ECC curve\n");
    return -1;
  }

  res = x509_verify_public_key(&pk_info->public_key_algorithm.algorithm_oid,
                               &pk_info->public_key_algorithm.parameters,
                               &pk_info->subject_public_key);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_pk_info_to_pk_ctx: Malformed Public Key\n");
    return res;
  }

  /* Set the pointers for the x and y cordinationes of the public key */
  pub_x_pos = &pk_info->subject_public_key.bit_string[1];
  pub_y_pos = pub_x_pos + key_length;

  /* Set the x and y cordinates of the public key */
  memcpy(pk_ctx->pub_x, pub_x_pos, key_length);
  memcpy(pk_ctx->pub_y, pub_y_pos, key_length);

  /* Set the private key */
  memset(pk_ctx->priv, 0, sizeof(pk_ctx->priv));

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_version(uint8_t **pos, uint8_t *end, uint8_t *version)
{
  int res = 0;
  uint32_t tmp = 1000;
  uint16_t length = 0;

  res = asn1_decode_tag(pos, end, &length, (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_version: [0] tag missing\n");
    return res;
  }

  res = asn1_decode_integer(pos, (*pos + length), &tmp);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_version: Could not decode integer\n");
    return res;
  }

  /* version = 2 is used for X.509v3 certificates */
  if((tmp != X509_VERSION_1) && (tmp != X509_VERSION_2) && (tmp != X509_VERSION_3)) {
    LOG_ERR("X.509 ERROR - x509_decode_version: unsupported version %d\n", (int)tmp);
    return -1;
  }

  /* Set the version */
  *version = (uint8_t)tmp;

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_subject(uint8_t **pos, uint8_t *end, asn1_tlv *subject)
{
  int res = 0;

  subject->tag = (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT);
  res = asn1_decode_tag(pos, end, &subject->length, subject->tag);
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_decode_issuer: issuer malformed\n");
    return -1;
  }

  /* Update pointers */
  subject->value = (*pos);
  (*pos) += subject->length;

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_issuer(uint8_t **pos, uint8_t *end, asn1_tlv *issuer)
{
  int res = 0;

  issuer->tag = (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT);
  res = asn1_decode_tag(pos, end, &issuer->length, issuer->tag);
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_decode_issuer: issuer malformed\n");
    return -1;
  }

  /* Update pointers */
  issuer->value = (*pos);
  (*pos) += issuer->length;

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_validity(uint8_t **pos, uint8_t *end, x509_validity *validity)
{
  int res = 0;
  uint16_t length = 0;

  res = asn1_decode_tag(pos, end, &length, (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT));
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_decode_validity: Could not decode Validity sequence\n");
    return res;
  }

  res = x509_decode_time(pos, end, &validity->not_before);
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_decode_validity: Could not decode Not Before\n");
    return res;
  }

  res = x509_decode_time(pos, end, &validity->not_after);
  if(res < 0) {
    LOG_ERR("X.509 ERROR: x509_decode_validity: Could not decode Not After\n");
    return res;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_time(uint8_t **pos, uint8_t *end, x509_time *time)
{

  int res = 0;
  uint16_t length = 0;

  if(**pos == ASN1_TAG_UTC_TIME) {
    res = asn1_decode_tag(pos, end, &length, ASN1_TAG_UTC_TIME);
    if(res >= 0) {
      res = x509_parse_utc_time(*pos, length, time);
    }
  } else if(**pos == ASN1_TAG_GENERALIZED_TIME) {
    res = asn1_decode_tag(pos, end, &length, ASN1_TAG_GENERALIZED_TIME);
    if(res >= 0) {
      res = x509_parse_generalized_time(*pos, length, time);
    }
  } else {
    LOG_ERR("X.509 ERROR - x509_decode_time: Unknown time format %02X\n", **pos);
    return -1;
  }
  /* Verify that the parse functions were successful */
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_time: Could not parse time\n");
    return res;
  }

  /* Verify that the time is valid */
  res = x509_verify_valid_time(time);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_time: Invalid time\n");
    return res;
  }

  /* Update pointer */
  (*pos) += length;

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_chars_to_int(uint8_t **pos, uint16_t len)
{
  char str[5];
  memset(str, 0, sizeof(str));

  /* Copy the pointer to a temporary location*/
  memcpy(str, (*pos), len);
  str[len + 1] = '\0';

  /* Update pointer */
  (*pos) += len;

  return atoi(str);
}
/*----------------------------------------------------------------------------*/
int
x509_parse_utc_time(uint8_t *buf, uint16_t buf_len, x509_time *time)
{

  if(buf_len < X509_UTC_TIME_MIN_LENGTH) {
    LOG_ERR("X.509 ERROR: UTC time shorter than minimum\n");
    return -1;
  }

  memset(time, 0, sizeof(x509_time));

  uint8_t *pos;
  pos = buf;

  /* Parse the year and covert it from a 2 digit format to a 4 digit format */
  time->year = (uint16_t)x509_chars_to_int(&pos, 2);
  /* Fix century, TODO: handle different centuries ? */
  time->year += X509_UTC_CENTURY;

  time->month = (uint8_t)x509_chars_to_int(&pos, 2);
  time->day = (uint8_t)x509_chars_to_int(&pos, 2);
  time->hour = (uint8_t)x509_chars_to_int(&pos, 2);
  time->minute = (uint8_t)x509_chars_to_int(&pos, 2);

  if(buf[buf_len - 1] == 'Z') {
    /* YYMMDDhhmm[ss]Z */
    time->format = UTC_TIME_Z;

    /* Handle the optional seconds */
    if(buf_len > 11) {
      time->second = (uint8_t)x509_chars_to_int(&pos, 2);
    }
  } else {
    /* YYMMDDhhmm[ss](+|-)hhmm */
    time->format = UTC_TIME_DIFF;

    /* Handle optional seconds */
    if(buf_len > 15) {
      time->second = (uint8_t)x509_chars_to_int(&pos, 2);
    }

    /* Set the sign */
    time->sign = (pos[0] == '-') ? -1 : 1;
    pos++;

    time->diff_hour = (uint8_t)x509_chars_to_int(&pos, 2);
    time->diff_minute = (uint8_t)x509_chars_to_int(&pos, 2);
  }

  /* x509_print_time(time); */

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_parse_generalized_time(uint8_t *buf, uint16_t buf_len, x509_time *time)
{

  if(buf_len < X509_G_TIME_MIN_LENGTH) {
    LOG_ERR("X.509 ERROR: Generalized time shorter than minimum\n");
    return -1;
  }

  uint8_t *pos;
  pos = buf;
  memset(time, 0, sizeof(x509_time));

  /* Determine what generalized format is used */
  if(buf[buf_len - 1] == 'Z') {
    time->format = G_TIME_UTC_ONLY;
  } else if((buf[buf_len - 5] == '-') || (buf[buf_len - 5] == '+')) {
    time->format = G_TIME_DIFF;
  } else {
    time->format = G_TIME_LOCAL_ONLY;
  }

  /* Set YYYYMMDDHH */
  time->year = (uint16_t)x509_chars_to_int(&pos, 4);
  time->month = (uint8_t)x509_chars_to_int(&pos, 2);
  time->day = (uint8_t)x509_chars_to_int(&pos, 2);
  time->hour = (uint8_t)x509_chars_to_int(&pos, 2);

  /* Parse [MM[SS[.fff]]] */
  if((buf_len > 10) && (buf[10] != 'Z') &&
     (buf[10] != '+') && (buf[10] != '-')) {
    time->minute = (uint8_t)x509_chars_to_int(&pos, 2);

    /* Set the seconds  */
    if((buf_len > 12) && (buf[12] != 'Z') &&
       (buf[12] != '+') && (buf[12] != '-')) {
      time->second = (uint8_t)x509_chars_to_int(&pos, 2);
    }

    /* Skip second fraction */
  }

  /* Set the diff time */
  if(time->format == G_TIME_DIFF) {
    pos = &buf[buf_len - 5];
    time->sign = (pos[0] == '-') ? -1 : 1;
    pos++;

    time->diff_hour = (uint8_t)x509_chars_to_int(&pos, 2);
    time->diff_minute = (uint8_t)x509_chars_to_int(&pos, 2);
  }

  x509_print_time(time);

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_decode_signature(uint8_t **sign_start, uint8_t *sign_end, asn1_bitstring *signature)
{
  int res = 0;

  res = asn1_decode_bit_string(sign_start, sign_end, signature);
  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_decode_signature: Could not decode signature bit-string\n");
    return res;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_set_signature_type(x509_algorithm_ID *signature_algorithm_tlv, x509_key_context *key_ctx)
{

  /* Check the what the signature algorithm oid is */
  if(oid_cmp(OID_ALGORITHM_ECDSA_WITH_SHA256,
             signature_algorithm_tlv->algorithm_oid.value,
             signature_algorithm_tlv->algorithm_oid.length) == 0) {
    key_ctx->sign = (uint8_t)ECDSA_WITH_SHA256;
  } else {
    LOG_ERR("X.509 ERROR - x509_set_signature_type: Unknown signature oid\n");
    return -1;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_public_key(asn1_tlv *algorithm_oid, asn1_tlv *parameters, asn1_bitstring *public_key)
{
  uint16_t key_length = 0;

  if(oid_cmp(OID_ID_EC_PUBLIC_KEY, algorithm_oid->value, algorithm_oid->length) == 0) {
    if(oid_cmp(OID_CURVE_NAME_SECP256R1, parameters->value, parameters->length) == 0) {
      key_length = ECC_DEFAULT_KEY_LEN;
    } else {
      LOG_ERR("X.509 ERROR - x509_verify_public_key: Unknown ECC CURVE\n");
      return -1;
    }

    /* Verify the length */
    if(public_key->length != (2 * key_length + 1)) {
      LOG_ERR("X.509 ERROR - x509_verify_public_key: Incorrect bit-string length %u expected %u\n",
               public_key->length, (2 * key_length + 1));
      return -1;
    }

    /* Verify compression */
    if(public_key->bit_string[0] != ECC_POINT_UNCOMPRESSED) {
      LOG_ERR("X.509 ERROR - x509_verify_public_key: Unsupported ECC compression %02X, expected %02X\n",
               public_key->bit_string[0], ECC_POINT_UNCOMPRESSED);
      return -1;
    }
  } else {
    LOG_ERR("X.509 ERROR - x509_verify_public_key: Unknown Public Key Algorithm\n");
    return -1;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_validity(x509_validity *cert_validity, x509_time *current_time)
{
  /* Verify that current_time is after the start of the validity range */
  if(x509_datetime_after(&cert_validity->not_before, current_time) < 0) {
    LOG_ERR("x509_verify_validity: Current time is before Not Before \n");
    return -1;
  }

  /* Verify that current_time is before the end of the validity range */
  if(x509_datetime_before(&cert_validity->not_after, current_time) < 0) {
    LOG_ERR("x509_verify_validity: Current time is after Not After \n");
    return -1;
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_valid_time(x509_time *time)
{

  /* Simple time validation, Only checks that the values are in the correct range.
   * Does not perform the following checks
   *  - If the year is a leap year
   *  - If a day is in a particular month e.g. 31. feb, is a valid
   *    date here because we assume that all months have the same range
   */
  if(((time->year >= X509_MIN_YEAR) && (time->year <= X509_MAX_YEAR))
     && ((time->month >= 1) && (time->month <= 12))
     && ((time->day >= 1) && (time->day <= 31))
     && ((time->hour >= 0) && (time->hour <= 23))
     && ((time->minute >= 0) && (time->minute <= 59))
     && ((time->second >= 0) && (time->second <= 59))) {
    return 0;
  }

  return -1;
}
/*----------------------------------------------------------------------------*/
int
x509_datetime_compare_to(x509_time *time1, x509_time *time2)
{
  int res = 0;
  /* TODO: Update the time based on time zones, Could be to much trouble*/

  /* Compare the dates in the two structures */
  res = x509_date_compare_to(time1, time2);

  if(res > 0) {
    return 1;
  } else if(res == 0) {
    res = x509_time_compare_to(time1, time2);
    if(res > 0) {
      return 1;
    } else if(res == 0) {
      return 0;
    }
  }

  return -1;
}
/*----------------------------------------------------------------------------*/
int
x509_date_compare_to(x509_time *time1, x509_time *time2)
{

  /* Compare the year, month and day in time1 and time2 */
  if(time1->year > time2->year) {
    return 1;
  } else if(time1->year == time2->year) {
    if(time1->month > time2->month) {
      return 1;
    } else if(time1->month == time2->month) {
      if(time1->day > time2->day) {
        return 1;
      } else if(time1->day == time2->day) {
        return 0;
      }
    }
  }

  return -1;
}
/*----------------------------------------------------------------------------*/
int
x509_time_compare_to(x509_time *time1, x509_time *time2)
{

  /* Compare the hour, minute and second of time1 and time2 */
  if(time1->hour > time2->hour) {
    return 1;
  } else if(time1->hour == time2->hour) {
    if(time1->minute > time2->minute) {
      return 1;
    } else if(time1->minute == time2->minute) {
      if(time1->second > time2->second) {
        return 1;
      } else if(time1->second == time2->second) {
        return 0;
      }
    }
  }

  return -1;
}
/*----------------------------------------------------------------------------*/
int
x509_datetime_after(x509_time *time, x509_time *current_time)
{
  int res = 0;

  /* Compare time and current_time */
  res = x509_datetime_compare_to(time, current_time);

  /* Check if time < current_time */
  if(res < 0) {
    return 0;
  }

  return -1;
}
/*----------------------------------------------------------------------------*/
int
x509_datetime_before(x509_time *time, x509_time *current_time)
{
  int res = 0;

  /* Compare time and current_time */
  res = x509_datetime_compare_to(time, current_time);

  /* Check if time >= current_time */
  if(res >= 0) {
    return 0;
  }

  return -1;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_cert_status(x509_certificate *cert)
{
  /* TODO: (Certificate Revocation) Implement revocation status checking, either CRLs or OCSP
   * or Something different */
  LOG_DBG("X.509 WARNING - x509_verify_cert_status: Certificate revocation checking not implemented!\n");

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_name(asn1_tlv *expected_name, asn1_tlv *name)
{
  /* Verify the pointers */
  if(expected_name == NULL || name == NULL) {
    LOG_ERR("X.509 ERROR - x509_verify_name: NULL pointer \n");
    return -1;
  }

  /* Verify the tags */
  if(expected_name->tag != name->tag) {
    LOG_ERR("X.509 ERROR - x509_verify_name: ASN.1 Tags don't match\n");
    return -1;
  }

  /* Verify the values of the expected_name and name */
  #if 0 < WITH_COMPRESSION && EST_DEBUG_X509
    LOG_DBG("Expected:\n");
    hdump(expected_name->value, name->length);
    LOG_DBG("\nGot:\n");
    hdump(name->value, name->length);
  #endif

  /* Verify the lengths */
  if(expected_name->length != name->length) {
    //printf("expected_name->value %s, name->value %s\n", expected_name->value, name->value);
    LOG_ERR("X.509 ERROR - x509_verify_name: ASN.1 Lengths don't match %d %d\n", expected_name->length, name->length);
    return -1;
  }

  /*
   * Ignore the issue with different tag-type values through only looking at the content of the tag value
   */
#define ISSUER_PREAMBLE_LEN 11

  if(memcmp(expected_name->value+ISSUER_PREAMBLE_LEN, name->value+ISSUER_PREAMBLE_LEN, name->length-ISSUER_PREAMBLE_LEN) != 0) {
    LOG_ERR("X.509 ERROR - x509_verify_name: ASN.1 Values don't match\n");
    return -1;
  }
  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_issuer(asn1_tlv *working_issuer_name, asn1_tlv *issuer_name)
{
  int res = 0;
  res = x509_verify_name(working_issuer_name, issuer_name);

  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_verify_issuer: working_issuer_name != issuer_name\n");
  }

  return res;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_subject(asn1_tlv *expected_subject_name, asn1_tlv *subject_name)
{
  int res = 0;
  res = x509_verify_name(expected_subject_name, subject_name);

  if(res < 0) {
    LOG_ERR("X.509 ERROR - x509_verify_subject: working_subject_name != subject_name\n");
  }

  return res;
}
/*----------------------------------------------------------------------------*/
int
x509_cert_is_self_signed(x509_certificate *cert)
{
  return x509_verify_issuer(&cert->issuer_name, &cert->subject_name) < 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_certificate(x509_certificate *cert, asn1_tlv *working_issuer_name,
                        x509_subject_pk_info *working_public_key_info, x509_time *current_time)
{
  /* (RFC 5280) 6.1.3. Basic Certificate Processing
   *  1. The signature on the certificate can be verified using
   *     working_public_key_algorithm, the working_public_key, and the
   *     working_public_key_parameters.
   *  2. The certificate validity period includes the current time.
   *  3. At the current time, the certificate is not revoked. This may be
   *     determined by obtaining the appropriate CRL, by status information, or
   *     by out of band mechanisms.
   *  4. The certificate issuer name is the working_issuer_name
   */
  int res = 0;
  static x509_key_context working_pub_key_ctx;

  /* Create key context from working_public_key_info */
  res = x509_pk_info_to_pk_ctx(working_public_key_info, &working_pub_key_ctx);
  if(res < 0) {
    return res;
  }

  /* Set the signature algorithm of the public key context from the cert */
  res = x509_set_signature_type(&cert->certificate_signature_algorithm,
                                &working_pub_key_ctx);
  if(res < 0) {
    return res;
  }

  /* Validate signature */
  res = x509_verify_signature(cert->tbs_cert_start, cert->tbs_cert_len, cert->sign_start,
                              cert->sign_len, &working_pub_key_ctx);
  if(res < 0) {
	  LOG_ERR("x509_verify_certificate: signature verify failed\n");
    return res;
  }

  /* Is current_time within the certificate validity  */
  if(current_time != NULL) {
    res = x509_verify_validity(&cert->validity, current_time);
    if(res < 0) {
      LOG_ERR("x509_verify_certificate: current_time not within validity range\n");
      return res;
    }
  } else {
    LOG_WARN("x509_verify_certificate: Current time not set, skipping time validation\n");
  }

  /* Is the certificate revoked? */
  /* res = x509_verify_cert_status(cert); */
  /* if(res < 0) { */
  /*   LOG_ERR("X.509 ERROR - x509_verify_certificate: The certificate is not valid\n"); */
  /*   return res; */
  /* } */

  /* Is the issuer name the working_issuer_name.
     working_issuer_name is the issuer distinguished name expected in the next
     certificate in the chain. The working issuer name is initialized to the trusted
     issuer name provided in the trust anchor information */
  res = x509_verify_issuer(working_issuer_name, &cert->issuer_name);
  if(res < 0) {
    LOG_ERR("x509_verify_certificate: The issuer name does not match the working issuer name \n");
    return res;
  }
  /* TODO: Verify extensions?, e.g. what the allowed
   * path length is and if it has the ca=true (maybe not here because we need to
   * know the position of the certificate in the path)????
   */

  return 0;
}
/*----------------------------------------------------------------------------*/
int
x509_verify_certificate_path(x509_certificate *path,
                             x509_certificate *trust_anchor, x509_time *current_time)
{
  /* This function performs the Basic Certification Path Validation algorithm
   * that is described in chapter 6 in RFC 5280
   */

  /* Initialization of variables used in the basic certification path validation */

  static x509_subject_pk_info working_public_key_info;
  static asn1_tlv working_issuer_name;
  uint16_t max_path_length;   /* Initialized to the longest path and decremented
                               * by 1 for each non self-signed certificate in the path */


  /* zero-initialize */
  memset(&working_issuer_name, 0, sizeof(asn1_tlv));
  memset(&working_public_key_info, 0, sizeof(x509_subject_pk_info));

  /* Initialization of the result and current certificate to validate */
  int res = 0;
  x509_certificate *current_cert;
  current_cert = path;
  /* Set the variables used to verify the next certificate */
  max_path_length = X509_MAX_CHAIN_LENGTH;
  memcpy(&working_issuer_name, &trust_anchor->subject_name, sizeof(asn1_tlv));
  memcpy(&working_public_key_info, &trust_anchor->pk_info, sizeof(x509_subject_pk_info));

#if STACK_CHECK_ENABLED
    LOG_DBG("stack_check_get_reserved_size() - stack_check_get_usage(): %d\n",(int)(stack_check_get_reserved_size() - stack_check_get_usage()));
#endif

  if(current_cert == NULL) {

    LOG_DBG("Check single CA cert only\n");
    res = x509_verify_certificate(trust_anchor, &working_issuer_name, &working_public_key_info, current_time);
    if(res < 0) {
      LOG_ERR("x509_verify_certificate: Invalid CA cert\n");
      return res;
    }
  } else {

    while((max_path_length > 0) && (current_cert != NULL)) {
      /* Verify the current certificate in the path */
      res = x509_verify_certificate(current_cert, &working_issuer_name, &working_public_key_info, current_time);

      if(res < 0) {
        LOG_ERR("x509_verify_certificate_path: Invalid path\n");
        return res;
      }

      /* Update the inputs to the validation function */
      max_path_length -= 1;
      working_issuer_name = current_cert->subject_name;
      working_public_key_info = current_cert->pk_info;

      /* Set the next certificate to verify */
      current_cert = current_cert->next;
    }
  }
  if(current_cert != NULL) {
    LOG_ERR("x509_verify_certificate_path: Certificate path too long\n");
    return -1;
  }

  /* Wrap up process */
  /* In RFC 5280 here is where the return value will be the working_public_key,
   * the working_public_key_algorithm and the working_public_key_parameters but
   * all of those parameters are stored in the last certificate in the path so
   * they can be accessed there so we return 0 to indicate a successful path
   * validation
   */
  return 0;
}
/*----------------------------------------------------------------------------*/
