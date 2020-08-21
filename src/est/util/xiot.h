#ifndef _XIOT_H_
#define _XIOT_H_

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>

/* String type defines */
#define XIOT_ISSUER_STRING_ENCODING ASN1_TAG_UTF8_STRING
#define XIOT_SUBJECT_STRING_ENCODING ASN1_TAG_UTF8_STRING



/* Limits for buffer sizes */
#define XIOT_MAX_SUBJECT_LENGTH 32
#define XIOT_MAX_ISSUER_LENGTH  32
#define XIOT_MAX_COMPRESSED     512
#define XIOT_MAX_DECOMPRESSED   1024

/* Constants to insert when constructing X.509 certificates */
#define XIOT_VERSION_INSERT     "\xA0\x03\x02\x01\x02"
#define XIOT_SIG_ALG_INSERT     "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02"
#define XIOT_SUB_PUB_INSERT     "\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42"  

/* Structure to hold extensions */
typedef struct xiot_ext{
    uint8_t         oid;
    bool            critical;
    uint8_t*        value;
    size_t          length;
    struct xiot_ext* next; 
}xiot_ext_t;

/* Structure to hold decoded certificates */
typedef struct xiot_cert{
    uint32_t        serial_number;
    //uint32_t        serial_number;
    char            issuer[XIOT_MAX_SUBJECT_LENGTH];
    size_t          issuer_length;
    struct tm       not_before;
    struct tm       not_after;
    char            subject[XIOT_MAX_SUBJECT_LENGTH];
    size_t          subject_length;
    bool            subject_ca;
    uint8_t         public_key[64];
    xiot_ext_t*     extensions;
    uint8_t         signature[64];
}xiot_cert_t;

/* Compress X.509 certificates.
 * 
 * compressed - pointer where to store the compressed certificate.
 * uncompressed - pointer to the certificate to compress.
 * 
 * returns size of compressed certificate.
 *
 * Note: Uncompressed certificates are binary ASN.1 and NOT
 *   base64 encoded. Compressed certificates are binary CBOR.
 */
size_t xiot_compress(uint8_t* compressed, const uint8_t* uncompressed, size_t length);

/* Decompress compressed certificates.
 *
 * decompressed - pointer where to store the decompressed certificate.
 * uncompressed - pointer to the compressed certificate to decompress.
 * 
 * returns size of decompressed certificate.
 */
size_t xiot_decompress(uint8_t* decompressed, const uint8_t* compressed, size_t length);

size_t xiot_decompress_chain(uint8_t* result, const uint8_t* compressed_chain);

/* Construct new X.509 certificate from xiot_cert_t structure.
 * 
 * decompressed - pointer where to store the new certificate.
 * cert - pointer to structure to construct from.
 *
 * returns size of constructed certificate.
 */
size_t xiot_construct(uint8_t* decompressed, xiot_cert_t* cert, uint8_t* ca_private);

/* Decode compressed certificate to xiot_cert_t structure.
 *
 * cert - pointer to struct that will contain decoded certificate.
 * compressed - pointer to compressed certificate to decode.
 *
 * returns 1 if success, otherwise 0.
 */
int xiot_decode_compressed(xiot_cert_t* cert, const uint8_t* compressed, size_t length);

/* Create compressed certificate from xiot_cert_t struture.
 * 
 * compressed - pointer where to store the new compressed certificate.
 * cert - pointer to structure to decode.
 *
 * returns size of new compressed certificate
 */
size_t xiot_encode_compressed(uint8_t* compressed, xiot_cert_t* cert);

/* Verifies that the signature of the certificate is valid.
 *
 * cert - pointer to decoded certificate to verify.
 * public_key - public key of CA that signed the certificate.
 * 
 * returns 1 if valid, otherwise 0
 */
int xiot_verify_signature(xiot_cert_t* cert, uint8_t* public_key);

/* Verify that certificate is valid at given time.
 *
 * cert - pointer to decoded certificate to verify.
 * time - time to check if valid.
 * 
 * returns 1 if valid, otherwise 0
 */
int xiot_verify_validity(xiot_cert_t* cert, time_t time);

time_t ext_mktime(struct tm *tmbuf); //well, need to be somewhere

//void hdump(const unsigned char *packet, int length);

static inline uint32_t uint32_to_int(const unsigned char *field)
{
  return ((uint32_t)field[0] << 24)
   | ((uint32_t)field[1] << 16)
   | ((uint32_t)field[2] << 8)
   | (uint32_t)field[3];
}



#ifdef XIOT_DEBUG
/* Print CBOR error message */
#define ERR_ASSERT(error, line) ((error == CN_CBOR_NO_ERROR) ? sleep(0) : printf("cn-cbor error: %d\nat line%d\n", error, line))
/* Print buffer in hexadecimal values */
void xiot_print_bytes(const uint8_t* buffer, size_t length);
#else
/* Do nothing when not debugging */
#define ERR_ASSERT(error, line) 
#endif //XIOT_DEBUG


#endif //_XIOT_H_
