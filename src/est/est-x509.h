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
 *          Definition of structures and functions for X.509 certificate
 *          decoding and encoding
 *
 * \author
 *         Rúnar Már Magnússon  <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#ifndef EST_X509_H
#define EST_X509_H

#include "est-asn1.h"
#include "est.h"
//#include "bigint.h"


#define SECP256R1_KEY_LEN_WORDS 8 /** Number of 32-bit words in a SECP256R1 key */
#define ECC_DEFAULT_KEY_LEN 32 // = (SECP256R1_KEY_LEN_WORDS * 4)
#define ECC_DEFAULT_SIGN_LEN 32 //

/* Compression types - RFC 5480 */
#define ECC_POINT_UNCOMPRESSED  0x04 /* MUST be supported */
#define ECC_POINT_COMPRESSED1   0x02 /* NOT SUPPORTED */
#define ECC_POINT_COMPRESSED2   0x03 /* NOT SUPPORTED */

#ifdef X509_CONF_MAX_STORED_CERTIFICATES
#define X509_MAX_STORED_CERTIFICATES X509_CONF_MAX_STORED_CERTIFICATES
#else
#define X509_MAX_STORED_CERTIFICATES 3 /**<- The number of certificates that are allocated default 6 */
#endif

#define X509_MAX_CHAIN_LENGTH 3
#define X509_UTC_TIME_MIN_LENGTH 11
#define X509_G_TIME_MIN_LENGTH 10
#define X509_UTC_CENTURY 2000   /**<- Assume that we are using utc dates after 2000 */
#define X509_MIN_YEAR 1900
#define X509_MAX_YEAR 3000

#define X509_EUI64_SUBJECT_SIZE 34 /**<- The size of the buffer to store the EUI-64 subject: 34 = 23 + 11 (11-22-33-44-55-66-77-88) */
#define TEST_ENROLL_SUBJECT_SIZE 29 //TODO /**<- The size of the buffer to store the test subject */
#if TEST_ENROLL_SUBJECT
#define ENROLL_SUBJECT_SIZE TEST_ENROLL_SUBJECT_SIZE
#else
#define ENROLL_SUBJECT_SIZE X509_EUI64_SUBJECT_SIZE
#endif

//#define X509_CBOR_EUI64_SUBJECT_SIZE 8 /** 6 or 8 */

#define X509_EUI64_DELIM "-"

#define X509_VERSION_1 0
#define X509_VERSION_2 1
#define X509_VERSION_3 2

/******************************************************************************
 * X.509 Structures
 ******************************************************************************/
/**
 * Different Time Formats used in generatlizedTime and UTCTime
 */
typedef enum x509_time_format {
  UTC_TIME_Z = 0,           /* YYMMDDhhmm[ss]Z                  (SUPPORTED) */
  UTC_TIME_DIFF = 1,        /* YYMMDDhhmm[ss](+|-)hhmm          (SUPPORTED) */
  G_TIME_LOCAL_ONLY = 2,    /* YYYYMMDDHH[MM[SS[.fff]]]         (SUPPORTED) */
  G_TIME_UTC_ONLY = 3,      /* YYYYMMDDHH[MM[SS[.fff]]]Z        (SUPPORTED) */
  G_TIME_DIFF = 4,          /* YYYYMMDDHH[MM[SS[.fff]]]+-HHMM   (SUPPORTED) */
} x509_time_format;

/**
 * Container for utcTime and generalTime
 *
 * Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 */
typedef struct x509_time {
  x509_time_format format;   /* x509_time_format */

  /* We need to store year, month, day, hour, minute, second */
  uint16_t year;    /* 0000-9999 */
  uint8_t month;    /* 1-12 */
  uint8_t day;      /* 1-12 */

  uint8_t hour;     /* 0-23 */
  uint8_t minute;   /* 0-59 */
  uint8_t second;   /* 0-59 */

  int sign;         /* Used in utcTIME: -1, 0 (sign not used), +1 */
  uint8_t diff_hour;
  uint8_t diff_minute;

  /* We ignore the second fraction used in generalizedTime */
} x509_time;

/**
 * Structure for validity
 *
 * Validity ::= SEQUENCE {
 *      notBefore      Time,
 *      notAfter       Time  }
 */
typedef struct x509_validity {
  x509_time not_before;
  x509_time not_after;
} x509_validity;

/**
 * Structure for Algorithm Identifier
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *                                 -- contains a value of the type
 *                                 -- registered for use with the
 *                                 -- algorithm object identifier value
 */
typedef struct x509_algorithm_ID {
  asn1_tlv algorithm_oid;   /* Object Identifier */
  asn1_tlv parameters;      /* Parameters */
} x509_algorithm_ID;

/**
 * Structure for SubjectPublicKeyInfo
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 *
 */
typedef struct x509_subject_pk_info {
  x509_algorithm_ID public_key_algorithm;
  asn1_bitstring subject_public_key;      /* BIT STRING */
} x509_subject_pk_info;

/**
 * Public-key Algorithm types
 */
typedef enum x509_pk_algo_type {
  ECC_PUBLIC_KEY = 1,
} x509_pk_algo_type;

/**
 * Signature Algorithm types
 */
typedef enum x509_sign_algo_type {
  ECDSA_WITH_SHA256 = 1,
} x509_sign_algo_type;

/**
 * Curve types
 */
typedef enum x509_ECDSA_CURVE {
  SECP256R1_CURVE = 1,
} x509_ECDSA_CURVE;

/**
 * Structure to store public key context
 * TODO find something better to store public key context
 */
typedef struct x509_key_context {
  uint8_t pk_alg;   /* From x509_pk_algo_type */
  uint8_t sign;   /* From x509_sign_algo_type */

//#if EST_WITH_ECC
  uint8_t curve;   /* From x509_ECDSA_CURVE */

  uint8_t priv[ECC_DEFAULT_KEY_LEN];
  uint8_t pub_x[ECC_DEFAULT_KEY_LEN];
  uint8_t pub_y[ECC_DEFAULT_KEY_LEN];
//#endif
} x509_key_context;

/**
 * Structure to store certificate information
 *
 *  Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signature            BIT STRING  }
 *
 * TBSCertificate  ::=  SEQUENCE  {
 *      version         [0]  Version DEFAULT v1,
 *      serialNumber         CertificateSerialNumber,
 *      signature            AlgorithmIdentifier,
 *      issuer               Name,
 *      validity             Validity,
 *      subject              Name,
 *      subjectPublicKeyInfo SubjectPublicKeyInfo,
 *      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version MUST be v2 or v3
 *      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version MUST be v2 or v3
 *      extensions      [3]  Extensions OPTIONAL
 *                           -- If present, version MUST be v3 --  }
 */
typedef struct x509_certificate {
  asn1_tlv cert_tlv;    /* Container for the certificate data */

  /* TBSCertificate fields */
  uint8_t version;                   /* Version ::= INTEGER {v1(0), v2(1), v3(2)} */

  asn1_tlv serial_number;            /* CertificateSerialNumber ::= INTEGER */
  x509_algorithm_ID signature_algorithm_ID;
  asn1_tlv issuer_name;

  /* Validity Period*/
  x509_validity validity;

  asn1_tlv subject_name;
  x509_subject_pk_info pk_info;

  asn1_bitstring issuer_unique_ID;        /* Optional */
  asn1_bitstring subject_unique_ID;       /* Optional */
  asn1_tlv extensions;                    /* Optional */

  /* Signature algorithm and Signature */
  x509_algorithm_ID certificate_signature_algorithm;

  /* Pointers used for signature checking
   *
   *   tbs_cert_start  sign_start
   *       v___________v___________
   *      |___________|____________|
   */
  uint8_t *tbs_cert_start;
  uint16_t tbs_cert_len;
  uint8_t *sign_start;
  uint16_t sign_len;
  asn1_bitstring certificate_signature;

  struct x509_certificate *next;   /* Next certificate in the chain */
} x509_certificate;

/******************************************************************************
 * X.509 Print functions
 ******************************************************************************/
/**
 * Prints the information in the certificate stored at cert
 * @param cert
 */
void x509_print_certificate(x509_certificate *cert);

/**
 * Prints the certificate chain that has a cert as head
 * @param cert the head of the chain
 */
void x509_print_certificate_chain(x509_certificate *cert);

/**
 * Prints the datetime stored in time
 * @param time the datetime to print
 */
void x509_print_time(x509_time *time);

/******************************************************************************
 * X.509 Memory management functions
 ******************************************************************************/
/**
 * Initializes the memory that is used for x509_certificate structures.
 * MUST be called before other x509_memb functions.
 */
void x509_memb_init();

/**
 * Zero-initializes a certificate
 * @param cert the certificate to initialize
 */
void x509_init_certificate(x509_certificate *cert);

/**
 * Allocates and initializes a new x509_certificate
 * @return If successful the function returns a pointer to the created certificate
 *  NULL otherwise
 */
x509_certificate *x509_memb_create_certificate();

/**
 * Removes the certificate chain with head at cert
 * @param cert the start of the certificate chain
 * @return 0 if successful, -1 otherwise
 */
int x509_memb_remove_certificates(x509_certificate *cert);

/******************************************************************************
 * X.509 Create default values
 ******************************************************************************/

/**
 * The value buffer needs to be pre-allocated and be at least
 * X509_EUI64_SUBJECT_SIZE (27 bytes)
 * @param subject the ASN.1 TLV to store the subject
 * @param value the buffer to store the subject
 * @param value_length the size of the value buffer
 */
int x509_set_eui64_subject(asn1_tlv *subject, uint8_t *value, uint16_t value_length);
int x509_set_subject(asn1_tlv *subject, uint8_t *value, uint16_t value_length);

/******************************************************************************
 * X.509 Decode/Encode functions
 ******************************************************************************/

/**
 * Decodes the certificate stored at *pos and ends at end
 * @param pos the start of the certificate
 * @param end the end to the certificate
 * @return A x509_certificate containing the data in the certificate, NULL otherwise
 */
x509_certificate *x509_decode_certificate(uint8_t **pos, uint8_t *end);

#if EST_WITH_COFFEE
/**
 * Decodes a certificate from file
 * @param buf A buffer to contain the certificate
 * @param buf_len The length of the buffer
 * @param type the type of certificate
 * @return A x509_certificate containing the information that was read from the file
 */
x509_certificate *x509_decode_certificate_from_file(uint8_t *buf, uint16_t buf_len, cert_file_type type);

/**
 * Returns the trust anchor, either from the implicit or explicit (preferred) db
 * @param buf a buffer to contain the certificate
 * @param buf_len the length of the buffer
 * @return A x509_certificate containing the certificate information of the trust anchor
 */
x509_certificate *x509_get_trust_anchor_from_file(uint8_t *buf, uint16_t buf_len);

/**
 * Returns the path from the trust anchor to an issuing CA.
 * @param buf a buffer to contain the certificates
 * @param buf_len the length of the buffer
 * @return An x509_certificate containing the certificate
 */
x509_certificate *x509_get_trust_anchor_path_from_file(uint8_t *buf, uint16_t buf_len);

/**
 * Writes a certificate to
 * @param cert The certificate to write
 * @param type The type of certificate
 * @return 0 if successful, -1 otherwise
 */
int x509_write_certificate_to_file(x509_certificate *cert, cert_file_type type);
#endif

/**
 * Decodes a ASN.1 encoded TBSCertificate
 * @param pos the start of the TBSCertificate
 * @param end the end of the TBSCertificate
 * @param cert the certificate to store the decoded certificate
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_tbs_certificate(uint8_t **pos, uint8_t *end, x509_certificate *cert);

/**
 * Encodes a TBSCertificate
 *
 * TODO: Decide if we need this functionality
 *
 * NOT IMPLEMENTED (We maybe do not need this since we store the certificates encoded
 * the EST client does not need to encode TBSCertifcate )
 * @param pos
 * @param start
 * @param cert
 * @return
 */
int x509_encode_tbs_certificate(uint8_t **pos, uint8_t *start, x509_certificate *cert);

/**
 * Decodes and validates the version of a TBSCertificate
 * @param pos points to the start of the version
 * @param end points to the end of the version
 * @param version variable to store the decoded version
 * @return 0 if successful and if the version is X.509v3, X.509v2 or X.509v1, -1 otherwise
 */
int x509_decode_version(uint8_t **pos, uint8_t *end, uint8_t *version);

/**
 * Decodes an algorithm identifier
 * @param pos points to the start of the algorithm identifier sequence
 * @param end points to the end of the algorithm identifier
 * @param alg_oid the ASN.1 TLV to store the algorithm oid
 * @param params the ASN.1 TLV to store the additional parameters for the algorithm
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_algorithm_identifier(uint8_t **pos, uint8_t *end, asn1_tlv *alg_oid, asn1_tlv *params);

/**
 * Encodes an algorithm identifier
 * @param pos the position were the encoded algorithm identifier ends
 * @param start the position that the encoded algorithm identifier can't exceed
 * @param alg_oid the algorithm oid to write
 * @param params the optional parameters to write, NULL if no parameters
 * @return the length of the encoded algorithm identifier, -1 otherwise
 */
int x509_encode_algorithm_identifier(uint8_t **pos, uint8_t *start, asn1_tlv *alg_oid, asn1_tlv *params);

/**
 * Decodes the subjectName of an TBSCertifcate
 * @param pos points to the subjectName sequence
 * @param end the end of the subjectName
 * @param subject the ASN.1 TLV to store the subjectName
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_subject(uint8_t **pos, uint8_t *end, asn1_tlv *subject);

/**
 * Encodes a subjectName, A subjectName is an constructed sequence of Name choices
 * @param pos the next position to write the encoded subjectName
 * @param start the position that the encoded algorithm identifier can't exceed
 * @param name an ASN.1 TLV that contains the subjectName
 * @return the length of the encoded subjectName, -1 otherwise
 */
int x509_encode_subject(uint8_t **pos, uint8_t *start, asn1_tlv *name);

/**
 * Decodes the issuerName of an TBSCertifcate
 * @param pos points to the issuerName sequence
 * @param end the end of the issuerName
 * @param subject the ASN.1 TLV to store the issuerName
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_issuer(uint8_t **pos, uint8_t *end, asn1_tlv *issuer);

/**
 * Encodes a issuerName. A issuerName is an constructed sequence of Name choices
 * @param pos the next position to write the encoded issuerName
 * @param start the position that the encoded algorithm identifier can't exceed
 * @param name an ASN.1 TLV that contains the issuerName
 * @return the length of the encoded issuerName, -1 otherwise
 */
int x509_encode_issuer(uint8_t **pos, uint8_t *start, asn1_tlv *name);

/**
 * Decodes the validity field of an TBSCertificate
 * @param pos the start of the validity
 * @param end the end of the validity
 * @param validity structure to store the validity period
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_validity(uint8_t **pos, uint8_t *end, x509_validity *validity);

/**
 * Decodes UTCTime and GeneralizedTime ASN.1 TLVs
 * @param pos the start of the time tag
 * @param end the end of the time tag
 * @param time structure to store the decoded time
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_time(uint8_t **pos, uint8_t *end, x509_time *time);

/**
 * Parses an ASCII encoded utc time string to a time structure
 * @param buf points to the buffer that holds the ASCII string (non zero terminated)
 * @param buf_len the length of the ascii string
 * @param time structure to hold the parsed time
 * @return 0 if successful, -1 otherwise
 */
int x509_parse_utc_time(uint8_t *buf, uint16_t buf_len, x509_time *time);

/**
 * Parses an ASCII encoded generalized time to a time structure
 * @param buf points to the buffer that holds the ASCII string (non zero terminated)
 * @param buf_len the length of the ascii string
 * @param time structure to hold the parsed time
 * @return 0 if successful, -1 otherwise
 */
int x509_parse_generalized_time(uint8_t *buf, uint16_t buf_len, x509_time *time);

/**
 * Encodes a SubjectPubliKeyInfo
 * @param pos the next position to write
 * @param start the position that we can't write over
 * @param pk_ctx structure the stores the SubjectPublicKeyInfo
 * @return the length of the encoded SubjectPublicKeyInfo, -1 otherwise
 */
int x509_encode_pk_info(uint8_t **pos, uint8_t *start, x509_key_context *pk_ctx);

/**
 * Decodes a chain of at least one certificate
 * @param pos the start of the first byte of the first certificate
 * @param start the last byte of the last certificate
 * @param head the first certificate in the chain
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_certificate_sequence(uint8_t **pos, uint8_t *end, x509_certificate **head);

/**
 * Decodes a SubjectPublicKeyInfo
 * @param pos the start of the SubjectPublicKeyInfo
 * @param end the last byte of the SubjectPublicKeyInfo
 * @param pk_info the structure to store the SubjectPublicKeyInfo
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_pk_info(uint8_t **pos, uint8_t *end, x509_subject_pk_info *pk_info);

/**
 * Converts a initialized x509_subject_pk_info to a x509_key_context by extracting
 * the public key stored in the context
 * @param pk_info the SubjectPublicKeyInfo to a
 * @param pk_ctx the key context to set (NOTE: The memory for the public key needs
 *        to be pre-allocated)
 * @return 0 if successful, -1 otherwise
 */
int x509_pk_info_to_pk_ctx(x509_subject_pk_info *pk_info, x509_key_context *pk_ctx);

/**
 * buffer (buffer + buf_len - 1)  sign_pos
 *  |            |                    |
 *  v____________v          _________ v
 * | Data to sign |        | Signature |
 * |______________|        |___________|
 *
 * Creates a signature over [pos, sign_start -1] and encodes it as an ASN.1
 * bit_string. sign_pos - sign_start MUST have enough space for the signature,
 * the ASN.1 length, the ASN.1 tag and the initial byte in the bit_string
 *
 * @param sign_pos The end of the buffer
 * @param sign_start The start of the position that we can't write over
 * @param buffer The start of the data to sign
 * @param buf_len The length of the data to sign
 * @param pk_ctx The key context used to generate the signature
 * @return 0 if successful, -1 otherwise
 */
int x509_encode_signature(uint8_t **sign_pos, uint8_t *sign_start, uint8_t *buffer,
                          uint16_t buf_len, x509_key_context *pk_ctx);

/**
 * Verifies a signature that was calculated over the the data in [buffer; sign_start -1]
 * with the public key stored in pk_ctx
 * @param buffer contains the data that was signed and the signature
 * @param buf_len total length of data
 * @param sign_start the position in buffer where the signature starts
 * @param sign_len the length of the signature
 * @param pk_ctx a public key context that is used to verify the signature
 * @return 0 if the signature verification was successful, -1 otherwise
 */
int x509_verify_signature(uint8_t *buffer, uint16_t buf_len, uint8_t *sign_start,
                          uint16_t sign_len, x509_key_context *pk_ctx, int flag);

/**
 * Decodes a signature bit-string
 * @param sign_start the start of the signature bit-string
 * @param sign_end the end of the signature bit-string
 * @param signature the structure to store the decoded signature information
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_signature(uint8_t **sign_start, uint8_t *sign_end, asn1_bitstring *signature);

/**
 * Sets the signature algorithm type in a key context from an Algorithm identifier
 * @param signature_algorithm_tlv the ASN.1 algorithmIdentifier
 * @param key_ctx the key context to set the signature type of
 * @return 0 if successful, -1 otherwise
 */
int x509_set_signature_type(x509_algorithm_ID *signature_algorithm_tlv, x509_key_context *key_ctx);

#if EST_WITH_ECC

/**
 * Creates and encodes an ECDSA signature. The  space for the signature needs to
 * be pre-allocated. Note that we always use 33 bytes for the r and s integer
 * values for SECP256R1.
 *
 * Ecdsa-Sig-Value  ::=  SEQUENCE  {
 *      r     INTEGER,
 *      s     INTEGER  }
 *
 * @param sign_pos the position to start writing the signature
 * @param sign_start the position that we can't write over
 * @param buffer the start of the data to sign
 * @param buf_len the length of the data to sign
 * @param priv_key the private key to use to sign the data
 * @param num_words the number of 32 bit words in the key used
 * @return the length of the signature if successful, -1 otherwise
 */
int x509_encode_ecdsa_signature(uint8_t **sign_pos, uint8_t *sign_start,
                                uint8_t *buffer, uint16_t buf_len, uint8_t *priv_key, uint16_t num_words);

/**
 * Encodes the signature component component as an ASN.1 Integer
 * @param sign_pos the position to write the signature component
 * @param sign_start the position that we can't write over
 * @param num_words the number of 32 bit words in the signature component
 * @param component the signature component
 * @return the encoded length if successful, -1 otherwise
 */
//int x509_encode_signature_component_old(uint8_t **sign_pos, uint8_t *sign_start,
//                                    uint16_t num_words, u_word *component);

int x509_encode_signature_component(uint8_t **sign_pos, uint8_t *sign_start,
		uint8_t *component, size_t component_len);
/**
 * Decodes a ASN.1 TLV Intger to a signature component
 * @param sign_pos the start of the integer signature component
 * @param sign_end the end of the signature component
 * @param num_words the number of 32 bit words in the signature component
 * @param component the component to write to
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_signature_component(uint8_t **sign_pos, uint8_t *sign_end,
                                    uint16_t num_words, asn1_tlv *component_tlv);

/**
 * Verify an ECDSA signature
 * @param buffer the start of the data was signed
 * @param buf_len the length of the signed data
 * @param sign_start points to the start of the signature bit-string
 * @param sign_len length of the signature
 * @param num_words the number of 32 bit words in the
 * @param pk_ctx the public key context to verify the signature
 * @return 0 if the verification was successful, -1 otherwise
 */
int x509_verify_ecdsa_signature(uint8_t *buffer, uint16_t buf_len,
                                uint8_t *sign_start, uint16_t sign_len, uint8_t num_words,
                                x509_key_context *pk_ctx, int flag);

/**
 * Finds the public key components
 *
 * From RFC 5480
 * ECPoint ::= OCTET STRING
 *
 * @param public_key the public key bit-string from the SubjectPublicKeyInfo
 * @param pub_x points to the start of the public key x component
 * @param pub_y points ot the start of the public key y component
 * @return 0 if successful, -1 otherwise
 */
int x509_decode_ecdsa_pub_key(asn1_bitstring *public_key, uint8_t **pub_x,
                              uint8_t **pub_y, uint16_t key_length);
#endif

/**
 * Helper function to calculate the length of a signature so we can allocate
 * space for it in buffers before writing any data in the buffer.
 * @param The X.509 key context with the used signature algorithm
 * @return 0 if the algorithm was not found, otherwise the length of the signature
 *         ASN.1 encoded
 */
uint16_t x509_signature_bit_string_length(x509_key_context *pk_ctx);

/******************************************************************************
 * X.509 Verify functions
 ******************************************************************************/

/**
 * TODO: Implement certificate verification according to RFC 5280 and RFC 6125
 */

/**
 * Verifies the certificate path that starts at path and ends with the certificate
 * that we need to verify (in this case Cert 3).
 *  ______________      ____________      ____________
 * |    Cert 1    |    |   Cert 2   |    |   Cert 3   |
 * |  Issued by   | -> |  Issued by | -> |  Issued by |
 * | trust_anchor |    |   Cert 1   |    |   Cert 2   |
 * |______________|    |____________|    |____________|
 *          ^
 *        path
 *
 * trust_anchor is either the end entity certificate or a CA certificate. If the
 * trust anchor is provided in the form of a self-signed certificate then the
 * the self signed certificate is not included as part of the certification path.
 * Cert1.next = Cert2 and Cert2.next = Cert3 and Cert3.next = NULL
 *
 * @param path is a certificate path ending with the certificate that we need to
 *        verify.
 * @parma trust_anchor is the certificate of an entity that we trust.
 * @return 0 if the verification was successful, -1 otherwise
 */
int x509_verify_certificate_path(x509_certificate *path,
                                 x509_certificate *trust_anchor, x509_time *current_time);

/**
 * Verifies the certificate stored in cert
 * @param cert the certificate to verify
 * @param working_issuer_name the expected issuer name
 * @param working_public_key_info the public key info of the public key to use to
 *  verify the ceritificate
 * @return 0 if the verification was successful, -1 otherwise
 */
int x509_verify_certificate(x509_certificate *cert, asn1_tlv *working_issuer_name,
                            x509_subject_pk_info *working_public_key_info, x509_time *current_time);

/**
 * Verifies a public key e.g. if it is of the correct length and uses the correct
 * compression
 * @param algorithm_oid the public key algorithm OID
 * @param parameters the additional parameters
 * @param public_key
 * @return 0 if the
 */
int x509_verify_public_key(asn1_tlv *algorithm_oid, asn1_tlv *parameters, asn1_bitstring *public_key);

/**
 * Verifies that current_time is within the validity range of the certificate.
 * @param cert_validity the validity of the certificate
 * @param current_time The current time (needs to be synchronized)
 * @return 0 if the certificate is not expired, -1 otherwise
 */
int x509_verify_validity(x509_validity *cert_validity, x509_time *current_time);

/**
 * Verifies that the time is a valid datetime
 * @param time the time to validate
 * @return 0 if the time is a valid datetime, -1 otherwise
 */
int x509_verify_valid_time(x509_time *time);

///**
// * Verifies a signature that was calculated over the the data in [buffer; sign_start -1]
// * with the public key stored in pk_ctx
// * @param buffer contains the data that was signed and the signature
// * @param buf_len total length of data
// * @param sign_start the position in buffer where the signature starts
// * @param sign_len the length of the signature
// * @param pk_ctx a public key context that is used to verify the signature
// * @return 0 if the signature verification was successful, -1 otherwise
// */
//int x509_verify_signature(uint8_t *buffer, uint16_t buf_len, uint8_t *sign_start,
//                          uint16_t sign_len, x509_key_context *pk_ctx);

/**
 * Verifies the status of a certificate e.g. if the certificate is revoked or not.
 * @param cert the certificate to verify the status of
 * @return 0 if the certificate is valid, -1 if the certificate is revoked
 */
int x509_verify_cert_status(x509_certificate *cert);

/**
 * Compares two X.509 names (issuer or subject) and verifies that they are the same
 * @param expected_name an ASN.1 TLV containing a name that is expected
 * @param name an ASN.1 TLV containing a name
 * @return 0 if expected_name is the same as name, -1 otherwise
 */
int x509_verify_name(asn1_tlv *expected_name, asn1_tlv *name);

/**
 * Verifies the issuer of a certificate, this function is part of the basic
 * certificate path processing.
 * @param working_issuer_name the expected issuer for the next certificate on the path.
 * @param issuer_name the issuer name of the certificate to verify
 * @return 0 if working_issuer_name is the same as the issuer_name, -1 otherwise
 */
int x509_verify_issuer(asn1_tlv *working_issuer_name, asn1_tlv *issuer_name);

/**
 * Verifies the subject name of a certificate, this function is part of the
 * enrollment process.
 * @param expected_subject_name the expected subject name of the certificate
 * @param subject_name the subject name of the certificate to verify
 * @return 0 if expected_subject_name is the same as subject_name, -1 otherwise
 */
int x509_verify_subject(asn1_tlv *expected_subject_name, asn1_tlv *subject_name);

/**
 * Checks if certificate is self-signed.
 * @param cert the certificate to check
 * @return 1 if certificate is self-signed, 0 otherwise
 */
int x509_cert_is_self_signed(x509_certificate *cert);

#if EST_WITH_ECC

/**
 * Verify an ECDSA signature
 * @param buffer the start of the data was signed
 * @param buf_len the length of the signed data
 * @param sign_start points to the start of the signature bit-string
 * @param sign_len length of the signature
 * @param num_words the number of 32 bit words in the
 * @param pk_ctx the public key context to verify the signature
 * @return 0 if the verification was successful, -1 otherwise
 */
//int x509_verify_ecdsa_signature(uint8_t *buffer, uint16_t buf_len,
//                                uint8_t *sign_start, uint16_t sign_len, uint8_t num_words,
//                                x509_key_context *pk_ctx);

#endif /* EST_WITH_ECC */

/******************************************************************************
 * X.509 Time helper functions
 ******************************************************************************/

/**
 * Checks if current_time is after time
 * @param time the time to check against
 * @param current_time the current time
 * @return 0 if current_time >= time, -1 otherwise
 */
int x509_datetime_after(x509_time *time, x509_time *current_time);

/**
 * Checks if current_time is before time
 * @param time the time to check against
 * @param current_time the current time
 * @return 0 if current_time <= time, -1 otherwise
 */
int x509_datetime_before(x509_time *time, x509_time *current_time);

/**
 * Compares two x509_time structures,
 * @param time1
 * @param time2
 * @return 0 if time1 == time2, -1 if time1 < time2, +1 if time1 > time2
 */
int x509_datetime_compare_to(x509_time *time1, x509_time *time2);

/**
 * Compares the dates(year,month,day) in two x509_time structures
 * @param time1
 * @param time2
 * @return 0 if the date in time1 is the same as the date in time2,
 *         1 if the date in time1 is after the date in time2
 *        -1 if the date in time1 is before the date in time2
 */
int x509_date_compare_to(x509_time *time1, x509_time *time2);

/**
 * Compares the time(hour,minute,second) in two x509_time structures
 * @param time1
 * @param time2
 * @return 0 if the time in time1 is the same as the time in time2,
 *         1 if the time in time1 is after the time in time2
 *        -1 if the time in time1 is before the time in time2
 */
int x509_time_compare_to(x509_time *time1, x509_time *time2);
int x509_time_compare_to_upto_min(x509_time *time1, x509_time *time2);
/**
 * Print current time
 */
void x509_print_ctime(void);

/**
 * Set current time
 */
void x509_set_ctime(char *str);

/**
 * Get current time
 */
x509_time *x509_get_ctime(void);

int fix_cacerts_order(x509_certificate *head); //For debugging

#endif /* EST_X509_H */
