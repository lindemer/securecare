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
 *          Implementations of the decode and encode of ASN.1 structures
 * \author
 *         Rúnar Már Magnússon  <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#include "est-asn1.h"

#include "stdlib.h"
#include "string.h"

#if STANDALONE_VERSION
#define LOG_MODULE "asn1"
#ifdef LOG_CONF_LEVEL_EST_ASN1
#define LOG_LEVEL LOG_CONF_LEVEL_EST_ASN1
#else
#define LOG_LEVEL LOG_LEVEL_ERR //DBG
#endif
#include "util/standalone_log.h"
#else
//#include "util/nrf_log_wrapper.h"
#include "nrf_log.h"
#define LOG_ERR           NRF_LOG_ERROR
#define LOG_WARN          LOG_WARN(...)//NRF_LOG_WARNING
#define LOG_INFO          //NRF_LOG_INFO
#define LOG_DBG           //NRF_LOG_DEBUG
#endif


//#if LOG_LEVEL == LOG_LEVEL_DBG
//#define EST_DEBUG_ASN1 1
//#endif


/*----------------------------------------------------------------------------*/
/* Macro to print out the value in an ASN.1 TAG */
#define PRINT_ASN1_VALUE(value, length){ \
    int j = 0; \
    if(length < 10) { \
      for(j = 0; j < length; j++) { \
        printf("%02X ", value[j]); \
      } \
    } else { \
      printf("%02X %02X %02X %02X ... %02X %02X %02X %02X ", \
               value[0], value[1], value[2], value[3], \
               value[length - 4], value[length - 3], \
               value[length - 2], value[length - 1]); \
    } \
}
/*----------------------------------------------------------------------------*/
void
asn1_print(asn1_tlv *tlv)
{

  if((tlv != NULL) && (tlv->tag != 0x00)) {
    printf("TAG: ");

    /* Print out the TAG */
    switch(tlv->tag) {
    case ASN1_TAG_BIT_STRING:
      printf("Bit-String");
      break;
    case ASN1_TAG_BOOLEAN:
      printf("Boolean");
      break;
    case ASN1_TAG_INTEGER:
      printf("Integer");
      break;
    case ASN1_TAG_OCTET_STRING:
      printf("Octet-String");
      break;
    case ASN1_TAG_NULL:
      printf("NULL");
      break;
    case ASN1_TAG_OID:
      printf("OID");
      break;
    case ASN1_TAG_UTF8_STRING:
      printf("UTF-8-String");
      break;
    case (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT):
    printf("Constructed Sequence");
      break;
    case (ASN1_TAG_SET | ASN1_P_C_BIT):
    printf("Constructed Set");
      break;
    case ASN1_TAG_PRINTABLE_STRING:
      printf("Printable-String");
      break;
    case ASN1_TAG_TELETEX_STRING:
      printf("Teletext-String");
      break;
    case ASN1_TAG_UTC_TIME:
      printf("UTC Time String");
      break;
    case ASN1_TAG_GENERALIZED_TIME:
      printf("Generalized Time");
      break;
    case ASN1_TAG_UNIVERSAL_STRING:
      printf("Universal-String");
      break;
    default:
      printf("%02X", tlv->tag);
      break;
    }

    printf(", LENGTH: %d", tlv->length);

    if(tlv->value != NULL) {
      printf(", VALUE: ");
      PRINT_ASN1_VALUE(tlv->value, tlv->length);
    }
  }
  printf("\n");
}
/*----------------------------------------------------------------------------*/
void
asn1_print_bit_string(asn1_bitstring *bitstring)
{
  if((bitstring != NULL) && (bitstring->bit_string != NULL)) {
    printf("TAG: Bit-String");
    printf(", LENGTH: %d, VALUE: ", bitstring->length);
    PRINT_ASN1_VALUE(bitstring->bit_string, bitstring->length);
    printf(", Unused bits %d\n", bitstring->zero_bits);
  } else {
    printf("Empty Bit-String\n");
  }
}
/*----------------------------------------------------------------------------*/
void
init_asn1_tlv(asn1_tlv *tlv)
{
  memset(tlv, 0, sizeof(asn1_tlv));
}
/*----------------------------------------------------------------------------*/
void
init_asn1_bit_string(asn1_bitstring *str)
{
  memset(str, 0, sizeof(asn1_bitstring));
}
/*----------------------------------------------------------------------------*/
int
asn1_decode_length(uint8_t **pos, uint8_t *end, uint16_t *length)
{
  /* Check that there is at least one byte remaining */
  *length = 0;
  if((end - *pos) < 1) {
    LOG_ERR("asn1_decode_length - Length is at least 1 byte\n");
    return -1;
  }

  uint8_t num_bytes = 0;

  /* Short form if bit 8 is 0, then bits 7-1 give the length*/
  if((**pos & 0x80) == 0) {
    *length = *(*pos)++;
  } else {
    /* Long form is  if bit 8 is 1
       - bits 7-1 + all additional octets give the length
     * in base 256, most significant digit first
     *
     * The ASN.1 spcification allows for 127 bytes for for the length
     * field but we will limit it to 2
     */

    /* bytes 7-1 give the number of bytes in the length field */
    num_bytes = (**pos & 0x7F);

    if(num_bytes > ASN1_MAX_LEN_BYTES || num_bytes == 0) {
      LOG_ERR("asn1_decode_length - Maximum length exceeded\n");
      return -1;
    }
    if((end - *pos) < (num_bytes + 1)) {
      /* number of bytes in the length field exceed the remaining
       * bytes in the ASN.1 item */
      LOG_ERR("asn1_decode_length - number of bytes in the length field exceed the remaining\n");
      return -1;
    }
    if(num_bytes == 1) {
      *length = (*pos)[1];
      (*pos) += 2;
    } else if(num_bytes == 2) {
      *length = (uint16_t)(*pos)[1] << 8 | (*pos)[2];
      (*pos) += 3;
    } else {
      LOG_ERR("asn1_decode_length - Length unrecognized\n");
      return -1;
    }
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_decode_length: Decoded: %d\n", (int)*length);
#endif
  return 0;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_length(uint8_t **pos, uint8_t *start, uint16_t length)
{

  if(length <= 0x7F) {
    /* Short format -  bit 8 = 0, bits 7-1 are the length */
    if((*pos - start) < 1) {
      LOG_ERR("asn1_encode_length - length does not fit buffer\n");
      return -1;
    }
    *--(*pos) = (uint8_t)length;

#if EST_DEBUG_ASN1
    LOG_DBG("asn1_encode_length: Length: (%d), Encoded: ", (int)1);
    PRINT_ASN1_VALUE((*pos), 1);
    LOG_DBG("\n");
#endif

    return 1;
  } else if(length <= 0xFF) {
    /* Long format - bit 8  = 1, bits 7-1 = number of additional octets
       Additional octets hold the length in base256 */
    if((*pos - start) < 2) {
      LOG_ERR("asn1_encode_length - length does not fit buffer\n");
      return -1;
    }

    *--(*pos) = (uint8_t)length;
    *--(*pos) = 0x81;     /* Long format 1 additional octet */

#if EST_DEBUG_ASN1
    LOG_DBG("asn1_encode_length: Length: (%d), Encoded: ", (int)2);
    PRINT_ASN1_VALUE((*pos), 2);
    LOG_DBG("\n");
#endif

    return 2;
  } else {

    if((*pos - start) < 3) {
      LOG_ERR("asn1_encode_length - length does not fit buffer\n");
      return -1;
    }

    /* We only support lengths smaller than 65535 bytes */
    *--(*pos) = (uint8_t)length % 256;
    *--(*pos) = (((uint8_t)length / 256) % 256);
    *--(*pos) = 0x82;
  }
#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_length: Length: (%d), Encoded: ", (int)3);
  PRINT_ASN1_VALUE((*pos), 3);
  LOG_DBG("\n");
#endif

  return 3;
}
/*----------------------------------------------------------------------------*/
int
asn1_supported_tag(uint8_t tag)
{

  switch(tag) {
  case ASN1_TAG_BOOLEAN:
  case ASN1_TAG_INTEGER:
  case ASN1_TAG_BIT_STRING:
  case ASN1_TAG_OCTET_STRING:
  case ASN1_TAG_NULL:
  case ASN1_TAG_OID:
  case ASN1_TAG_SEQUENCE:
  case ASN1_TAG_SET:
  case ASN1_TAG_PRINTABLE_STRING:
  case ASN1_TAG_UTC_TIME:
  case ASN1_TAG_GENERALIZED_TIME:
  case ASN1_TAG_UNIVERSAL_STRING:
  case ASN1_TAG_UTF8_STRING:
  case ASN1_TAG_TELETEX_STRING:
  case (ASN1_TAG_SEQUENCE | ASN1_P_C_BIT):
  case (ASN1_TAG_SET | ASN1_P_C_BIT):
    break;
  default:
    return -1;
  }
  return 0;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_tag(uint8_t **pos, uint8_t *start, uint8_t tag)
{

  if(*pos - start < 1) {
    LOG_ERR("asn1_encode_tag - tag does not fit in buffer\n");
    return -1;
  }

  /* Write tag and update pointer */
  *--(*pos) = tag;

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_tag: Length: (%d), Encoded: ", (int)1);
  PRINT_ASN1_VALUE((*pos), 1);
  LOG_DBG("\n");
#endif
  return 1;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_length_and_tag(uint8_t **pos, uint8_t *start, uint8_t tag, uint16_t length)
{
  int res = 0;
  uint16_t len = 0;

  /* Encode the length */
  res = asn1_encode_length(pos, start, length);
  if(res < 0) {
    return res;
  } else {
    len += res;
  }

  /* Encode the ASN.1 tag */
  res = asn1_encode_tag(pos, start, tag);
  if(res < 0) {
    return res;
  } else {
    len += res;
  }
#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_length_and_tag: Length: (%d), Encoded: ", (int)len);
  PRINT_ASN1_VALUE((*pos), len);
  LOG_DBG("\n");
#endif
  return len;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_buffer(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len)
{

  if(*pos - start < (int)len) {
    LOG_ERR("asn1_decode_buffer - buffer does not fit destination\n");
    return -1;
  }

  /* Copy buffer */
  (*pos) -= len;
  memcpy(*pos, buffer, len);

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_buffer: Length: (%d), Encoded: ", (int)len);
  PRINT_ASN1_VALUE((*pos), len);
  LOG_DBG("\n");
#endif
  return (int)len;
}
/*----------------------------------------------------------------------------*/
/* Check if the tag is of the correct type and advance the
 * pointer to the start of value*/
int
asn1_decode_tag(uint8_t **pos, uint8_t *end, uint16_t *length, uint8_t tag)
{
  if((end - *pos) < 1) {
    LOG_ERR("asn1_decode_tag - end is less than pos\n");
    return -1;
  }

  if(**pos != tag) {
    /* Incorrect tag*/
    LOG_ERR("asn1_decode_tag - Unexpected tag: %02X, expected: %02X\n",
             **pos, tag);
    return -1;
  }

  (*pos)++;

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_decode_tag: Decoded: %02X\n", tag);
#endif
  return asn1_decode_length(pos, end, length);
}
/*----------------------------------------------------------------------------*/
int
asn1_decode_integer(uint8_t **pos, uint8_t *end, uint32_t *value)
{

  int res;
  uint16_t length = 0;

  res = asn1_decode_tag(pos, end, &length, ASN1_TAG_INTEGER);
  if(res < 0) {
    LOG_ERR("asn1_decode_integer - Could not decode tag\n");
    return res;
  }

  if(length > ASN1_MAX_INTEGER_LENGTH || (**pos & 0x80) != 0) {
    /* The size does not fit uint32_t or is negative*/
    LOG_ERR("asn1_decode_integer - Size exceeds 4 bytes or is negative\n");
    return -1;
  }

  *value = 0;

  while(length > 0) {
    *value = (*value << 8) | **pos;
    (*pos)++;
    length--;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_decode_integer: Decoded: %d\n", (int)value);
#endif
  return 0;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_integer(uint8_t **pos, uint8_t *start, uint32_t value)
{
  uint16_t length = 0;
  int res;
  uint32_t tmp = 0;   /* Fits uint32_t */

  if(*pos - start < 1) {
    LOG_ERR("asn1_encode_integer - Buffer to small\n");
    return -1;
  }

  tmp = value;
  *--(*pos) = (uint8_t)tmp;
  length += 1;

  /* Convert the integer to octets one byte at a time */
  if((tmp >> 8) != 0) {
    *--(*pos) = (uint8_t)(tmp >> 8);
    length += 1;
    if((tmp >> 16) != 0) {
      *--(*pos) = (uint8_t)(tmp >> 16);
      length += 1;
      if(((tmp >> 24) != 0) && ((tmp >> 24) <= 0x7F)) {
        *--(*pos) = (uint8_t)(tmp >> 24);
        length += 1;
      } else {
        LOG_ERR("ASN.1 ERROR: asn1_encode_integer - Larger than 2147483647\n");
        return -1;
      }
    }
  }

  /* Handle the case when the integer does not fit into the 7 bits in the first
   * byte, the first bit in the first bite is the sign and we only support
   * positive integers */
  if((value > 0) && (**pos & 0x80)) {
    if(*pos - start < 1) {
      LOG_ERR("ASN.1 ERROR: asn1_encode_integer - buffer to small for integer\n");
      return -1;
    }

    *--(*pos) = 0x00;
    length += 1;
  }

  /* Write the length and tag */
  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_INTEGER, length);
  if(res < 0) {
    LOG_ERR("ASN.1 ERROR: asn1_encode_integer - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_integer: Length: (%d), Encoded: ", (int)length);
  PRINT_ASN1_VALUE((*pos), length);
  LOG_DBG("\n");
#endif
  return length;
}
/*----------------------------------------------------------------------------*/
int
asn1_decode_boolean(uint8_t **pos, uint8_t *end, uint8_t *value)
{
  uint16_t length = 0;
  int res = 0;

  res = asn1_decode_tag(pos, end, &length, ASN1_TAG_BOOLEAN);
  if(res < 0) {
    LOG_ERR("asn1_decode_boolean - Could not decode tag\n");
    return res;
  }

  if(length != 1) {
    /* Bool is only one byte */
    LOG_ERR("asn1_decode_boolean - Unexpected length: %u, expected: 1\n",
             length);
    return -1;
  }

  if(**pos != 0) {
    /* Non-zero value => TRUE */
    *value = ASN1_TRUE;
  } else {
    /* Zero => FALSE */
    *value = ASN1_FALSE;
  }
  (*pos)++;

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_decode_boolean: Decoded: %uhh\n", (unsigned int)value);
#endif
  return 0;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_boolean(uint8_t **pos, uint8_t *start, uint8_t value)
{
  uint16_t length = 0;
  int res = 0;

  if(*pos - start < 1) {
    LOG_ERR("asn1_encode_boolean - Buffer to small\n");
    return -1;
  }

  if(value) {
    *--(*pos) = ASN1_TRUE;
  } else {
    *--(*pos) = ASN1_FALSE;
  }
  length += 1;

  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_BOOLEAN, length);
  if(res < 0) {
    LOG_ERR("asn1_encode_boolean - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_boolean: Length: (%d), Encoded: ", (int)length);
  PRINT_ASN1_VALUE((*pos), length);
  LOG_DBG("\n");
#endif
  return length;
}
/*----------------------------------------------------------------------------*/
int
asn1_decode_bit_string(uint8_t **pos, uint8_t *end, asn1_bitstring *str)
{

  int res = 0;

  res = asn1_decode_tag(pos, end, &str->length, ASN1_TAG_BIT_STRING);
  if(res < 0) {
    LOG_ERR("asn1_decode_bit_string - Could not decode tag\n");
    return res;
  }

  /* First byte is the number of unused bits */
  if(str->length < 1) {
    LOG_ERR("ASN.1 ERROR: asn1_decode_bit_string - bit string can't be less than 1 byte\n");
    return -1;
  }

  /* Remove the initial byte with the zero bits from the start of the bit string */
  str->length -= 1;
  str->zero_bits = **pos;

  if(str->zero_bits > 7) {
    LOG_ERR("ASN.1 ERROR: asn1_decode_bit_string - The number of zero bits can't exceed 7 bits\n");
    return -1;
  }
  (*pos)++;

  str->bit_string = *pos;
  *pos += str->length;

  if(*pos != end) {
    LOG_ERR("ASN.1 ERROR: asn1_decode_bit_string - bit string not aligned with end\n");
    return -1;
  }
#if EST_DEBUG_ASN1
  LOG_DBG("asn1_decode_bit_string: Decoded: ");
  asn1_print_bit_string(str);
  LOG_DBG("\n");
#endif
  return 0;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_bit_string(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t num_bits)
{

  uint16_t str_length = 0;
  uint16_t length = 0;
  int res = 0;

  str_length = num_bits / ASN1_NUM_BITS_OCTET;

  if((num_bits % ASN1_NUM_BITS_OCTET) != 0) {
    str_length += 1;
  }

  if(*pos - start < (str_length + 1)) {
    LOG_ERR("asn1_encode_bit_string - Destination to small\n");
    return -1;
  }

  /* Write the bit-string */
  res = asn1_encode_buffer(pos, start, buffer, str_length);
  if(res < 0) {
    LOG_ERR("asn1_encode_bit_string - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

  /* Write the number of unused bits in the initial byte */
  *--(*pos) = (uint8_t)(str_length * ASN1_NUM_BITS_OCTET - num_bits);
  length += 1;

  /* Write the tag and length */
  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_BIT_STRING, length);
  if(res < 0) {
    LOG_ERR("asn1_encode_bit_string - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_bit_string: Length: (%d), Encoded: ", (int)length);
  PRINT_ASN1_VALUE((*pos), length);
  LOG_DBG("\n");
#endif
  return length;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_octet_string(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len)
{

  int res = 0;
  uint16_t length = 0;

  /* Write the Octet-string */
  res = asn1_encode_buffer(pos, start, buffer, len);
  if(res < 0) {
    LOG_ERR("asn1_encode_octet_string - Could not encode buffer\n");
    return res;
  } else {
    length += res;
  }

  /* Write the length and tag */
  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_OCTET_STRING, length);
  if(res < 0) {
    LOG_ERR("asn1_encode_octet_string - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_octet_string: Length: (%d), Encoded: ", (int)length);
  PRINT_ASN1_VALUE((*pos), length);
  LOG_DBG("\n");
#endif
  return length;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_oid(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len)
{
  int res = 0;
  uint16_t length = 0;

  /* Write the OID stored in the buffer */
  res = asn1_encode_buffer(pos, start, buffer, len);
  if(res < 0) {
    LOG_ERR("asn1_encode_oid - Could not encode buffer\n");
    return res;
  } else {
    length += res;
  }

  /* Write the length and tag */
  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_OID, length);
  if(res < 0) {
    LOG_ERR("asn1_encode_oid - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_oid: Length: (%d), Encoded: ", (int)length);
  PRINT_ASN1_VALUE((*pos), length);
  LOG_DBG("\n");
#endif
  return length;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_printable_string(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len)
{

  int res = 0;
  uint16_t length = 0;

  /* Write the printable string stored in the buffer */
  res = asn1_encode_buffer(pos, start, buffer, len);
  if(res < 0) {
    LOG_ERR("asn1_encode_printable_string - Could not encode buffer\n");
    return res;
  } else {
    length += res;
  }

  /* Write the length and tag */
  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_PRINTABLE_STRING, length);
  if(res < 0) {
    LOG_ERR("asn1_encode_printable_string - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_printable_string: Length: (%d), Encoded: ", (int)length);
  PRINT_ASN1_VALUE((*pos), length);
  LOG_DBG("\n");
#endif
  return length;
}
/*----------------------------------------------------------------------------*/
int
asn1_encode_null(uint8_t **pos, uint8_t *start)
{
  uint16_t length = 0;
  int res = 0;

  res = asn1_encode_length_and_tag(pos, start, ASN1_TAG_NULL, 0);
  if(res < 0) {
    LOG_ERR("asn1_encode_null - Could not encode length and tag\n");
    return res;
  } else {
    length += res;
  }

#if EST_DEBUG_ASN1
  LOG_DBG("asn1_encode_null: Length: (%d), Encoded: ", (int)length);
  PRINT_ASN1_VALUE((*pos), length);
  LOG_DBG("\n");
#endif
  return length;
}
/*----------------------------------------------------------------------------*/
int
asn1_get_tlv_encoded_length(asn1_tlv *tlv)
{
  /* Check if pointer is valid */
  if(tlv == NULL) {
    LOG_ERR("asn1_get_tlv_encoded_length - pointer is null\n");
    return -1;
  }
  /* Check if length is too long */
  if(tlv->length > ASN1_MAX_VALUE_LENGTH) {
    LOG_ERR("asn1_get_tlv_encoded_length - Length is too long\n");
    return -1;
  }

  uint16_t cert_length = tlv->length;
  if(cert_length <= 127) {
    cert_length += 2;    /*length is 1 bytes, 1 byte tag */
  } else if(cert_length <= 255) {
    cert_length += 3;    /*length is 2 bytes, 1 byte tag */
  } else if(cert_length > 256) {
    cert_length += 4;   /*length is 3 bytes, 1 byte tag */
  }

  return cert_length;
}
/*----------------------------------------------------------------------------*/
