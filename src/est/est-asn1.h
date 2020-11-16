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
 *          Structures for ASN.1 definitions for the EST protocol

 * \author
 *         Rúnar Már Magnússon <rmma@kth.se>
 *         Tómas Þór Helgason <helgas@kth.se>
 */

#ifndef EST_ASN1_H_
#define EST_ASN1_H_

//#include "est-debug.h.ignore"
#include "stdlib.h"
#include "stdint.h"
#include "stdio.h"
#include "inttypes.h"

#if EST_DEBUG_ASN1
#define ASN1_DBG(...) printf(__VA_ARGS__)
#else
#define ASN1_DBG(...)
#endif

/** ASN.1 TAGS - 1 otctet
 *
 * | 8 | 7 |  6  | 5 | 4 | 3 | 2 | 1 |
 * | Class | P/C |    Tag Number     |
 *
 */

/* ASN.1 Universal Class Tags */
#define ASN1_TAG_BOOLEAN                 0x01
#define ASN1_TAG_INTEGER                 0x02
#define ASN1_TAG_BIT_STRING              0x03
#define ASN1_TAG_OCTET_STRING            0x04
#define ASN1_TAG_NULL                    0x05
#define ASN1_TAG_OID                     0x06
#define ASN1_TAG_UTF8_STRING             0x0C
#define ASN1_TAG_SEQUENCE                0x10
#define ASN1_TAG_SET                     0x11
#define ASN1_TAG_PRINTABLE_STRING        0x13
#define ASN1_TAG_TELETEX_STRING          0x14
#define ASN1_TAG_UTC_TIME                0x17
#define ASN1_TAG_GENERALIZED_TIME        0x18
#define ASN1_TAG_UNIVERSAL_STRING        0x1C

#define ASN1_TAG_KEY_USAGE               "\x55\x1D\x0F"
#define ASN1_TAG_KEY_USAGE_DIGITAL_SIGN  "\x03\x02\x07\x80"


/* The Constructed bit is used when the ASN.1 structure holds further TLV values
   if it is 0 then the ASN.1 TLV is primative*/
#define ASN1_P_C_BIT                    0x20

/* ASN.1 tag classes - We only use universal */
#define ASN1_CLASS_UNIVERSAL            0x00
#define ASN1_CLASS_APPLICATION          0x40
#define ASN1_CLASS_CONTEXT_SPECIFIC     0x80
#define ASN1_CLASS_PRIVATE              0xC0

/* We only support ASN.1 items of length 2^(16)-1 bytes*/
#define ASN1_MAX_LEN_BYTES          2  /* Fits in uint16_t */
#define ASN1_MAX_SEQUENCE_LENGTH    0  /* Number of items we allow in a sequence */
#define ASN1_MAX_INTEGER_LENGTH     4  /* We only support 32 bit integers - 4 bytes */
#define ASN1_MAX_VALUE_LENGTH       65531 /* The max length of the value in an ASN.1 TLV */

/* Define TRUE and FALSE*/
#define ASN1_TRUE   1 /* If the boolean value is TRUE the octet shall be non-zero */
#define ASN1_FALSE  0 /* If the boolean value is FALSE the octet shall be zero */

#define ASN1_NUM_BITS_OCTET 8   /* The number of bits in an octet */

/**
 * Structure that stores the ASN.1 Type-length-value
 */
typedef struct asn1_tlv {
  uint8_t tag;              /* Tag from the universal class tags */
  uint16_t length;          /* Size in octets */
  uint8_t *value;     /* Pointer to the buffer holding the value */
} asn1_tlv;

/* Structure to hold bit-strings */
typedef struct asn1_bitstring {
  uint16_t length;
  uint8_t zero_bits;       /* Bits that are not used at the end of the string */
  uint8_t *bit_string;
} asn1_bitstring;

/**
 * Prints out the TAG, Length and Value of the ASN.1 structure tlv
 * @param tlv the structure to print information about
 */
void asn1_print(asn1_tlv *tlv);

/**
 * Prints out the TAG, Length and Value and unused bits of an ASN.1 bit-string
 * @param bitstring the bit-string to print information about
 */
void asn1_print_bit_string(asn1_bitstring *bitstring);

/* Encoding and decoding
 *
 *  *pos            |<-Length->end
 *    v_____________v__________v
 *   |Type | Length |   Value   |
 *   |_____|________|___________|
 *
 *   ----> Decoding read octets from left to right
 *
 *  start           |<-Length->(*pos)
 *    v_____________v__________v
 *   |Type | Length |   Value   |
 *   |_____|________|___________|
 *
 *   <---- Encoding write octets from right to left
 */

/**
 * Zero initializes the ASN.1 TLV tag
 * @param tlv the ASN.1 TLV to initialize
 */
void init_asn1_tlv(asn1_tlv *tlv);

/**
 * Zero initializes the bit-string str
 * @param str the bit-string to initialize
 */
void init_asn1_bit_string(asn1_bitstring *str);

/**
 * Decode the length of a ASN.1 structure stored in a buffer. After the operation
 * the pos pointer has been updated to point at the value field.
 *
 * @param pos - A pointer to pointer that points to the length field
 * @param end - The end of the buffer
 * @param length - Variable that stores the decoded length field
 * @return 0 if successful -1 otherwise
 */
int asn1_decode_length(uint8_t **pos, uint8_t *end, uint16_t *length);

/**
 * Encode the length of a ASN.1 structure stored in a buffer. After the
 * operation the pos pointer has been updated to point at the tag field.
 *
 * @param pos - A pointer to pointer that points to the length field
 * @param start - The start of the buffer
 * @param length - The length to encode
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_length(uint8_t **pos, uint8_t *start, uint16_t length);

/**
 * Decode an ASN.1 tag stored in a buffer and update the pos pointer to point
 * at the value in the ASN.1 TLV.
 *
 * @param pos points at the start of the ASN.1 TLV
 * @param end points at the end of the TLV
 * @param length a variable to hold the value in the TLV
 * @param tag the tag to decode
 * @return 0 if successful -1 otherwise
 */
int asn1_decode_tag(uint8_t **pos, uint8_t *end, uint16_t *length, uint8_t tag);

/**
 * Encode an ANS.1 tag to a buffer
 *
 * @param pos - A pointer to pointer that points to the place in a buffer
 *              where the encoded tag field should be written.
 * @param start - The start of the
 * @param tag - The tag to encode
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_tag(uint8_t **pos, uint8_t *start, uint8_t tag);

/**
 * Encodes the length and tag of an ASN.1 TLV. The length and tag are
 * encoded backwards in the buffer e.g. pos >= start
 *
 * @param pos the position in the buffer to write next
 * @param start the position that we can't write over e.g. pos >= start
 * @param tag the tag to encode
 * @param length the length of the value in the ASN.1 TLV
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_length_and_tag(uint8_t **pos, uint8_t *start, uint8_t tag, uint16_t length);

/**
 * Decodes a positive integer to value from an ASN.1 TLV. We only support
 * 32 bit positive integers
 * @param pos the position of the integer tag
 * @param end the end of the ASN.1 TLV that stores the integer
 * @param value the variable that will store the decoded integer
 * @return 0 if successful -1 otherwise
 */
int asn1_decode_integer(uint8_t **pos, uint8_t *end, uint32_t *value);

/**
 * Encode an integer that is up to 32 bits to a buffer
 * @param pos points to the end of the encoded integer
 * @param start points to the start of the buffer or a position
 * @param value the integer to encode
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_integer(uint8_t **pos, uint8_t *start, uint32_t value);

/**
 * Decode a boolean ASN.1 TLV
 * @param pos the position of the ASN1_TAG_BOOLEAN tag
 * @param end the end of the ASN.1 TLV
 * @param value the decoded value (0x01 if TRUE, 0x00 if FALSE)
 * @return 0 if successful -1 otherwise
 */
int asn1_decode_boolean(uint8_t **pos, uint8_t *end, uint8_t *value);

/**
 * Encode a boolean value to buffer
 * @param pos the position of the buffer that we will write to next
 * @param start the position we will not write over
 * @param value the boolean value to write
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_boolean(uint8_t **pos, uint8_t *start, uint8_t value);

/**
 * Encodes the values stored in buffer to [(*pos) - length;(*pos)]
 * @param pos the next position in a buffer to write to
 * @param start the position that we won't write over
 * @param buffer the octets that we will write
 * @param len the length of the buffer
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_buffer(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len);

/**
 * Decode a bit-string to the bit-string str
 * @param pos the start of the ASN.1 bit-string
 * @param end the end of the ASN.1 bit-string
 * @param str the bit-string structure to store information about the bit-string
 * @return 0 if successful -1 otherwise
 */
int asn1_decode_bit_string(uint8_t **pos, uint8_t *end, asn1_bitstring *str);

/**
 * Encodes the bit-string stored in buffer of length num_bits bits as an ASN.1
 * bit-string ending at pos
 * @param pos the ending position of the ASN.1 bit-string
 * @param start the position that we won't write over
 * @param buffer the buffer that stores the bit-string
 * @param num_bits the length of the bit-string in bits
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_bit_string(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t num_bits);

/**
 * Encodes the octet string stored at buffer
 * @param pos the next position to write
 * @param start the position that the encoded buffer can't exceed
 * @param buffer the buffer that stores the octet string
 * @param len the length of the octet string
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_octet_string(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len);

/**
 * Encodes the OID stored in the buffer of length len as an ASN.1 TLV
 * @param pos the next position to write
 * @param start the position that we can't write over
 * @param buffer the buffer that stores the OID
 * @param len the length of the OID
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_oid(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len);

/**
 * Encodes a printable string stored in buffer as an ASN.1 TLV
 * @param pos the next position to write
 * @param start the position that the TLV can't exceed
 * @param buffer the buffer that stores the printable string
 * @param len the length of the printable string in octets
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_printable_string(uint8_t **pos, uint8_t *start, uint8_t *buffer, uint16_t len);

/**
 * Encodes NULL as an ASN.1 TLV
 * @param pos the next position to write
 * @param start the position that pos can't exceed
 * @return encoded length if successful -1 otherwise
 */
int asn1_encode_null(uint8_t **pos, uint8_t *start);

/**
 * Checks if tag is supported
 * @param tag - The tag to check
 * @return 0 if supported -1 otherwise
 */
int asn1_supported_tag(uint8_t tag);

/**
 * Returns the encoded length of a ASN.1 TLV
 * @param tlv - the ASN.1 TLV to get the length from
 * @return the encoded length if successful -1 otherwise
 */
int asn1_get_tlv_encoded_length(asn1_tlv *tlv);

#endif /* EST_ASN1_H_ */
