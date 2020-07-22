#ifndef EST_DTLS_H
#define EST_DTLS_H

#include "../est/est.h"
#include "dtls.h"
/* #include "cert-parser.h" */

PROCESS_NAME(est_dtls_process);

#define PSK_MODE 0
#define PKI_MODE 1

/* This struct holds pointers to different components of a Certificate in
 * process.
 *
 */
typedef struct dtls_certificate_context_t {
  unsigned char *TBSCertificate;
  uint16_t TBSCertificate_len;
  unsigned char *issuer;
  uint16_t issuer_len;
  unsigned char *subject;
  uint16_t subject_len;
  unsigned char *subject_pub_key;
  uint16_t subject_pub_key_len;
  unsigned char *signature;
} dtls_certificate_context_t;

/* DTLS connect using PSK or PKI mode, callback when connection ok or failed */
void
est_dtls_connect(int mode, void (*callback)(void));

/* Return non-zero if DTLS is connected, otherwise zero */
int
est_dtls_connected(void);

/* DTLS disconnect */
void
est_dtls_disconnect(void);

/**
 * tinyDTLS callback: initiate the DTLS certificate from EST database
 */
void est_client_set_dtls_ecdsa_certificate(dtls_ecdsa_certificate_t *ecdsa_certificate);

/**
 * tinyDTLS callback: initiate the DTLS CA info from EST database
 */
void est_client_set_dtls_ca_info(dtls_ca_info_t *ca_info);

/**
 * tinyDTLS callback: verify certifiate against the TA certificate in cert-store
 */
int est_client_verify_certificate(uint8_t *certificate, uint16_t certificate_len, dtls_certificate_context_t *cert_ctx);
#endif
