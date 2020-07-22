/*
 * Copyright (c) 2020, RISE AB.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef DTLS_SETTING_H_
#define DTLS_SETTING_H_

#include <coap2/coap.h>
#include "est-x509.h"

struct pki_info_t {
  unsigned char *fts_cert_buf; //[2048];
  unsigned char *ets_cert_buf; //[PKI_ENROLLED_TS_LEN];
  unsigned char *factory_cert_buf; //[512];
  unsigned char *enrolled_cert_buf; //[PKI_ENROLLED_CERT_LEN];
  x509_certificate *ca_cert;
  x509_certificate *factory_cert;
  x509_certificate *enrolled_cert;
  unsigned char *factory_key;
  unsigned char *enrollment_key;
  int fts_cert_buf_len;
  int ets_cert_buf_len;
  int factory_cert_buf_len;
  int enrolled_cert_buf_len;
  uint8_t factory_key_len;
  uint8_t enrollment_key_len;
};

struct libcoap_info_t {
	coap_context_t *ctx;
	coap_session_t *session;
};

/** Protocol level for TLS.
 *  Here, the same socket protocol level for TLS as in Linux was used.
 */
#define SOL_TLS 282
#define SOL_TLS_CREDENTIALS 283


/**
 *  @defgroup secure_sockets_options Socket options for TLS
 *  @{
 */

/** Socket option to select TLS credentials to use. It accepts and returns an
 *  array of sec_tag_t that indicate which TLS credentials should be used with
 *  specific socket.
 */
#define TLS_SEC_TAG_LIST 1
/** Write-only socket option to set hostname. It accepts a string containing
 *  the hostname (may be NULL to disable hostname verification). By default,
 *  hostname check is enforced for TLS clients.
 */
#define TLS_HOSTNAME 2
/** Socket option to select ciphersuites to use. It accepts and returns an array
 *  of integers with IANA assigned ciphersuite identifiers.
 *  If not set, socket will allow all ciphersuites available in the system
 *  (mebdTLS default behavior).
 */
#define TLS_CIPHERSUITE_LIST 3
/** Read-only socket option to read a ciphersuite chosen during TLS handshake.
 *  It returns an integer containing an IANA assigned ciphersuite identifier
 *  of chosen ciphersuite.
 */
#define TLS_CIPHERSUITE_USED 4
/** Write-only socket option to set peer verification level for TLS connection.
 *  This option accepts an integer with a peer verification level, compatible
 *  with mbedTLS values:
 *    - 0 - none
 *    - 1 - optional
 *    - 2 - required
 *
 *  If not set, socket will use mbedTLS defaults (none for servers, required
 *  for clients).
 */
#define TLS_PEER_VERIFY 5
/** Write-only socket option to set role for DTLS connection. This option
 *  is irrelevant for TLS connections, as for them role is selected based on
 *  connect()/listen() usage. By default, DTLS will assume client role.
 *  This option accepts an integer with a TLS role, compatible with
 *  mbedTLS values:
 *    - 0 - client
 *    - 1 - server
 */
#define TLS_DTLS_ROLE 6

/** @} */

/* Valid values for TLS_PEER_VERIFY option */
#define TLS_PEER_VERIFY_NONE 0 /**< Peer verification disabled. */
#define TLS_PEER_VERIFY_OPTIONAL 1 /**< Peer verification optional. */
#define TLS_PEER_VERIFY_REQUIRED 2 /**< Peer verification required. */

/*
 * Compare with:
 */
//#define MBEDTLS_SSL_VERIFY_NONE                 0
//#define MBEDTLS_SSL_VERIFY_OPTIONAL             1
//#define MBEDTLS_SSL_VERIFY_REQUIRED             2

/* Valid values for TLS_DTLS_ROLE option */
#define TLS_DTLS_ROLE_CLIENT 0 /**< Client role in a DTLS session. */
#define TLS_DTLS_ROLE_SERVER 1 /**< Server role in a DTLS session. */

#define LIBCOAP_CONTEXT_TYPE 0
#define LIBCOAP_SESSION_TYPE 1


/** TLS credential types */

enum tls_credential_type {
  /** Unspecified credential. */
  TLS_CREDENTIAL_NONE,

  /**
   * One or more trusted CA certificates. Use this to authenticate the enrollment
   * server(s).
   * Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_INITIAL_TRUSTSTORE,
  /**
   * One or more trusted CA certificates. Use this to authenticate any server
   * Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_ENROLLED_TRUSTSTORE,
  /** A trusted CA certificate. Use this to authenticate remote servers.
   *  Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_CA_CERTIFICATE,

  /** A public server certificate. Use this to register your own server
   *  certificate. Should be registered together with a corresponding
   *  private key. Used with certificate-based ciphersuites.
   */
  //TLS_CREDENTIAL_SERVER_CERTIFICATE,
  TLS_CREDENTIAL_FACTORY_CERTIFICATE,

  /** A public server certificate. Use this to register your own enrolled
   *  certificate. Should be registered together with a corresponding
   *  private key. Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_ENROLLED_CERTIFICATE,

  /** Private key. Should be registered together with a corresponding
   *  factory certificate. Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_FACTORY_KEY,

  /** Private key. Should be registered together with a corresponding
   *  enrolledcertificate. Used with certificate-based ciphersuites.
   */
  TLS_CREDENTIAL_ENROLLMENT_KEY,

  /** Pre-shared key. Should be registered together with a corresponding
   *  PSK identity. Used with PSK-based ciphersuites.
   */
  TLS_CREDENTIAL_PSK,

  /** Pre-shared key identity. Should be registered together with a
   *  corresponding PSK. Used with PSK-based ciphersuites.
   */
  TLS_CREDENTIAL_PSK_ID
};

typedef enum {
  COAP_GET = 1,
  COAP_POST,
  COAP_PUT,
  COAP_DELETE
} coap_method_t;

int tls_credential_add(enum tls_credential_type type, void *cred, uint16_t credlen);
/*---------------------------------------------------------------------------*/
int tls_credential_get(enum tls_credential_type type, void *cred, uint16_t *credlen);

int libcoap_save_setting(int coap_setting_type, void *setting);
int libcoap_get_setting(int coap_setting_type, void *setting);

#endif /* PROJECT_CONF_H_ */
