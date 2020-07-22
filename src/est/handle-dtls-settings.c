/*
 * Copyright (c) 2020, RISE Research Institutes of Sweden AB.
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
 */
//#ifndef UIP_CONF_DTLS
//#define UIP_CONF_DTLS 1
//#endif

#include <errno.h>
#include <stdio.h> /* Debug / for printf */
#include <string.h>
#include "dtls-settings.h"
#include "est-base64.h"

#include "log.h"
#define LOG_MODULE "settings"
#define LOG_LEVEL LOG_LEVEL_DBG

//static dtls_context_t *dtls_context = NULL; //TODO, maybe link with existing dtls-struct

static struct pki_info_t pki_info;
static struct libcoap_info_t libcoap_info;

//int dtls_settings_init() {
//	pki_info = malloc(sizeof ())
//}
/*---------------------------------------------------------------------------*/
//int
//verify_certificate(struct dtls_context_t *ctx, uint8_t *certificate, uint16_t certificate_len,
//                              dtls_handshake_parameters_t *config)
//{
//
//  LOG_DBG("Start of verify_certificate\n");
//  struct cng_socket *sock = (struct cng_socket *)dtls_get_app_data(ctx);
//  struct dtls_certificate_context_t cert_ctx;
//  memset(client_buffer, 0, sizeof(client_buffer));
//  uint8_t *pos = certificate;
//  uint8_t *end;
//  x509_certificate *cert = NULL;
//  x509_certificate *top_cert = NULL;
//  end = pos + certificate_len;
//
//  //printf("Certificate_len is %d\n", certificate_len);
//
//#if 0 < WITH_COMPRESSION
//  /* Decode the certificate */
//
//  if(COMPRESSED_CERT_SIGNATURE_1 == certificate[0]) {
//    LOG_DBG("Decompress\n");
//
//    hdump(pos,certificate_len);
//    static uint8_t decompressed[XIOT_MAX_DECOMPRESSED];
//    size_t decompressed_size = xiot_decompress(decompressed, pos, certificate_len);
//    pos = decompressed;
//    end = pos + decompressed_size;
//    LOG_DBG("Done decompressing\n");
//  } else {
//    LOG_DBG("Uncompressed cert\n");
//  }
//#endif
//
//  top_cert = x509_decode_certificate(&pos, end);
//  if(top_cert == NULL) {
//    LOG_ERR("COULD NOT DECODE DTLS Certificate\n");
//    return -1;
//  }
//
//  cert = top_cert;
//  /* We only want the last cert if it is a chain */
//  while(cert->next != NULL) {
//    cert = cert->next;
//  }
//
//#if EST_WITH_COFFEE
//  x509_certificate *ca_cert = NULL, *path = NULL, *tmp_cert;
//  memset(client_buffer, 0, sizeof(client_buffer));
//  pos = client_buffer;
//  uint16_t len = sizeof(client_buffer);
//  uint16_t ca_len = 0;
//
//  LOG_DBG("est_client_verify_certificate - Loading certificates from flash\n");
//
//  int state = cert_store_get_state();
//  if(state == CERT_STORE_EXP_DB_USED) {
//    ca_cert = x509_decode_certificate_from_file(pos, len, EXPLICIT_TA);
//  } else if(state == CERT_STORE_IMP_DB_USED) {
//    ca_cert = x509_decode_certificate_from_file(pos, len, IMPLICIT_TA);
//  }
//  /* ca_cert = x509_get_trust_anchor_from_file(pos, len); */
//  if(!ca_cert) {
//    LOG_DBG("EST ERROR: x509_decode_certificate_from_file returns NULL\n");
//    return -1;
//  }
//
//  if(ca_cert != NULL) {
//    ca_len = asn1_get_tlv_encoded_length(&ca_cert->cert_tlv);
//    pos += ca_len;
//    len -= ca_len;
//    if(state == CERT_STORE_EXP_DB_USED) {
//      path = x509_decode_certificate_from_file(pos, len, EXPLICIT_PATH);
//    } else if(state == CERT_STORE_IMP_DB_USED) {
//      path = x509_decode_certificate_from_file(pos, len, IMPLICIT_PATH);
//    }
//    /* path = x509_get_trust_anchor_path_from_file(pos, len); */
//  }
//  LOG_DBG("est_client_verify_certificate DTLS certificate path validation\n");
//
//  tmp_cert = path;
//
//  /* Find the end of the ca path and add the certificate to verify */
//  while(tmp_cert->next != NULL) {
//    tmp_cert = tmp_cert->next;
//  }
//  tmp_cert->next = cert;
//
//  LOG_DBG("DTLS certificate path validation\n");
//
//  int res = x509_verify_certificate_path(path, ca_cert, x509_get_ctime());
//
//  if(res < 0) {
//    LOG_DBG("ERROR: est_client_verify_certificate returns %d\n", res);
//    return res;
//  } else {
//    LOG_DBG("DTLS certificate verified\n");
//  }
//  tmp_cert->next = NULL;
//  x509_memb_remove_certificates(ca_cert);
//  x509_memb_remove_certificates(path);
//
//#else
//  /* Temporary certificate verification */
//  //x509_certificate *tmp_cert;
//  //tmp_cert = est_session.ca_head;
//  //TODO: work is here!
//  LOG_INFO("Only verifying single certificate!\n");
////  tmp_cert = conn.dtls.pki_info.ca_cert;
////  /* Find the end of the ca path */
////  while(tmp_cert->next != NULL) {
////    tmp_cert = tmp_cert->next;
////  }
////  tmp_cert->next = cert;
////  //x509_certificate *signing_cert =
//  //int res = x509_verify_certificate_path(est_session.ca_head->next, est_session.ca_head, x509_gettime());
//  //int res = x509_verify_certificate_path(conn.dtls.pki_info.ca_cert.next, conn.dtls.pki_info.ca_cert, x509_gettime());
//  //int res = x509_verify_certificate_path(NULL, conn.dtls.pki_info.ca_cert, x509_get_ctime());
//    //conn.dtls.pki_info.ca_cert->next = top_cert;
//    //int res = x509_verify_certificate_path(conn.dtls.pki_info.ca_cert->next, conn.dtls.pki_info.ca_cert, x509_get_ctime());
//#if STACK_CHECK_ENABLED
//  LOG_DBG("stack_check_get_reserved_size(), stack_check_get_usage(), diff: %d, %d, %d\n",(int)(stack_check_get_reserved_size()), (int)(stack_check_get_usage()), (int)(stack_check_get_reserved_size() - stack_check_get_usage()));
//  //show_time();
//#endif
//    int res = x509_verify_certificate_path(top_cert, conn.dtls.pki_info.ca_cert, x509_get_ctime());
//
//
//  if(res < 0) {
//    LOG_ERR("verify_certificate failed\n");
//    return res;
//  } else {
//    LOG_DBG("DTLS certificate verified\n");
//  }
//  /* Reset the end of the path */
//  //tmp_cert->next = NULL;
//#endif
//
//  /* Extract the public key without the ECC compression type byte */
//  //cert_ctx->subject_pub_key = (unsigned char *)&cert->pk_info.subject_public_key.bit_string[1];
//  cert_ctx.subject_pub_key = (unsigned char *)&cert->pk_info.subject_public_key.bit_string[1];
//
//  x509_memb_remove_certificates(top_cert);
//
////Below was in dtls.c / cert version
//
//   LOG_DBG("Check_certificate: Certificate valid.\n");
//  //  data = old_data; //restore
//  //  printf("Old data starts with %x\n", data[0]);
//
//  memcpy(config->keyx.ecdsa.other_pub_x, cert_ctx.subject_pub_key,
//      sizeof(config->keyx.ecdsa.other_pub_x));
//
//  memcpy(config->keyx.ecdsa.other_pub_y, cert_ctx.subject_pub_key +
//      sizeof(config->keyx.ecdsa.other_pub_x),
//      sizeof(config->keyx.ecdsa.other_pub_y));
//
//  return 0;
//}
//
/*---------------------------------------------------------------------------*/
/* Compare with Zephyr / sockets_tls.c:
 * struct dtls_timing_context {}
 *
 *
 *
 *
 */
/*---------------------------------------------------------------------------*/
int tls_opt_hostname_set(const void *optval, uint16_t optlen)
{

//  if (mbedtls_ssl_set_hostname(&context->tls->ssl, optval) != 0) {
//    return -EINVAL;
//  }
//
//  context->tls->options.is_hostname_set = true;

  return 0;

}
/*---------------------------------------------------------------------------*/
int tls_opt_ciphersuite_list_set(const void *optval, uint16_t optlen)
{
  int cipher_cnt;

  if (!optval) {
    return -EINVAL;
  }

  if (optlen % sizeof(int) != 0) {
    return -EINVAL;
  }

  cipher_cnt = optlen / sizeof(int);

  LOG_ERR("tls_opt_ciphersuite_list_set - todo %c", cipher_cnt);
  //TODO
//  /* + 1 for 0-termination. */
//  if (cipher_cnt + 1 > ARRAY_SIZE(context->tls->options.ciphersuites)) {
//    return -EINVAL;
//  }
//
//  memcpy(context->tls->options.ciphersuites, optval, optlen);
//  context->tls->options.ciphersuites[cipher_cnt] = 0;

  return 0;
}

/*---------------------------------------------------------------------------*/
int tls_opt_peer_verify_set(const void *optval, uint16_t optlen)
{
  int *peer_verify;

  if (!optval) {
    return -EINVAL;
  }

  if (optlen != sizeof(int)) {
    return -EINVAL;
  }

  peer_verify = (int *)optval;

  if (*peer_verify != TLS_PEER_VERIFY_NONE &&
      *peer_verify != TLS_PEER_VERIFY_OPTIONAL &&
      *peer_verify != TLS_PEER_VERIFY_REQUIRED) {
    return -EINVAL;
  }

  //todo
  //context->tls->options.verify_level = *peer_verify;

  return 0;
}

/*---------------------------------------------------------------------------*/
int tls_opt_dtls_role_set(const void *optval, uint16_t optlen)
{
  int *role;

  if (!optval) {
    return -EINVAL;
  }

  if (optlen != sizeof(int)) {
    return -EINVAL;
  }

  role = (int *)optval;
  if (*role != TLS_DTLS_ROLE_CLIENT &&
      *role != TLS_DTLS_ROLE_SERVER) {
    return -EINVAL;
  }

  //context->tls->options.role = *role;

  return 0;
}

int
internal_cert_to_memory(void *cred, int is_ca_cert)
{

  x509_certificate *tmp_cert = NULL;
  /* Allocate memory for certificate */
  tmp_cert = cred;
  uint8_t *buffer;
  int buf_len = 0;
  if(is_ca_cert) {
    buffer = pki_info.ets_cert_buf;
    buf_len = pki_info.ets_cert_buf_len;
  } else {
    buffer = pki_info.enrolled_cert_buf;
    buf_len = pki_info.enrolled_cert_buf_len;
  }

  int offset = 0;
  //memcpy(cert, cred, sizeof(x509_certificate)); //vs credlen // TODO / Check
  //pki_info.ca_cert = cert;

  memset(buffer, 0, buf_len);

  while(tmp_cert != NULL) {
    int cert_length = asn1_get_tlv_encoded_length(&tmp_cert->cert_tlv);
    if(cert_length < 0) {
      LOG_ERR("store_to_session_buffer: certificate tlv encoded length\n");
      return cert_length;
    }
    if((offset + cert_length) > buf_len) {
      LOG_ERR("store_to_session_buffer: buffer to small for all certificates\n");
      return -1;
    }
    uint8_t *tmp_cert_start = tmp_cert->cert_tlv.value -
      (cert_length - tmp_cert->cert_tlv.length);
    memcpy(buffer + offset, tmp_cert_start, cert_length);
    offset += cert_length;
    tmp_cert = tmp_cert->next;
  }
    /* Decode the new certificate data in the session buffer */
    uint8_t *pos = buffer;
    tmp_cert = NULL;
    int res = x509_decode_certificate_sequence(&pos, buffer + offset, &tmp_cert);
    if(res < 0) {
      LOG_ERR("to_session_buffer: Could not decode certificate saved in memory\n");
      return res;
    }

    /* Set correct pointers to the new decoded certificate data */
    if(tmp_cert != NULL) {
          if(is_ca_cert) {
            pki_info.ca_cert = tmp_cert;
          } else {
            pki_info.enrolled_cert = tmp_cert;
          }

    } else {
      LOG_ERR("to_session_buffer: NULL pointer session cert\n");
      return -1;
    }
    return 1;

}

int libcoap_save_setting(int coap_setting_type, void *setting) {
  if(LIBCOAP_SESSION_TYPE == coap_setting_type) {
    libcoap_info.session = (coap_session_t *) setting;
    return 0;
  }
  if(LIBCOAP_CONTEXT_TYPE == coap_setting_type) {
    libcoap_info.ctx = (coap_context_t *) setting;
  }
  return -1;
}

int libcoap_get_setting(int coap_setting_type, void *setting) {
  if(LIBCOAP_SESSION_TYPE == coap_setting_type) {
    memcpy(setting, libcoap_info.session, sizeof(coap_session_t));
    return 0;
  }
  if(LIBCOAP_CONTEXT_TYPE == coap_setting_type) {
	  //memcpy(setting, libcoap_info.ctx, sizeof(coap_context_t));
	  setting = libcoap_info.ctx;
	  return 0;
  }
  return -1;
}

int tls_credential_add(enum tls_credential_type type, void *cred, uint16_t credlen)
{
  int res = 0;
  switch (type) {

  case TLS_CREDENTIAL_INITIAL_TRUSTSTORE:
    LOG_DBG("TLS_CREDENTIAL_INITIAL_TRUSTSTORE // Warning, will mess up original data buffer. credlen = %d\n", credlen);
    credlen = est_base64_decode_block_inplace((char *)cred, credlen);
    pki_info.fts_cert_buf = (unsigned char*)cred;
    pki_info.fts_cert_buf_len = credlen;
    pki_info.ca_cert = x509_decode_certificate((uint8_t **)&cred, (cred+credlen));
    //TODO, change to chain of certs
    //(uint8_t **pos, uint8_t *end)
    //x509_print_certificate(pki_info.ca_cert);
    /* Also, we need to init ecc somewhere. Let's do it here for now */
    //new_ecc_init();
  break;

  case TLS_CREDENTIAL_ENROLLED_TRUSTSTORE:
    LOG_DBG("TLS_CREDENTIAL_ENROLLED_TRUSTSTORE - setting pointer only. credlen = %d\n", credlen);
    pki_info.ets_cert_buf = (unsigned char*)cred;
    pki_info.ets_cert_buf_len = credlen;
  break;

  case TLS_CREDENTIAL_ENROLLED_CERTIFICATE:
    LOG_DBG("TLS_CREDENTIAL_ENROLLED_CERTIFICATE - setting pointer only. credlen = %d\n", credlen);
    pki_info.enrolled_cert_buf = (unsigned char*)cred;
    pki_info.enrolled_cert_buf_len = credlen;
  break;


  case TLS_CREDENTIAL_CA_CERTIFICATE:
    LOG_DBG("SET TLS_CREDENTIAL_CA_CERTIFICATE -- ERROR, use initial truststore\n");
    res = -1; //internal_cert_to_memory(sock, cred, 1);

  break;

    case TLS_CREDENTIAL_FACTORY_CERTIFICATE:
      LOG_DBG("TLS_CREDENTIAL_FACTORY_CERTIFICATE // Warning, will mess up original data buffer. credlen = %d\n", credlen);
      credlen = est_base64_decode_block_inplace((char *)cred, credlen);
      pki_info.factory_cert_buf = (unsigned char*)cred;
      pki_info.factory_cert_buf_len = credlen;
      pki_info.factory_cert = x509_decode_certificate((uint8_t **)&cred, (cred+credlen));
      //x509_print_certificate(pki_info.factory_cert);

    break;

    case TLS_CREDENTIAL_FACTORY_KEY:
      LOG_DBG("TLS_CREDENTIAL_FACTORY_KEY. Currently stored as reference. credlen = %d\n", credlen);
      pki_info.factory_key = (uint8_t *)cred;
      pki_info.factory_key_len = credlen;
      break;

    case TLS_CREDENTIAL_ENROLLMENT_KEY:
      LOG_DBG("TLS_CREDENTIAL_ENROLLED_KEY. Currently stored as reference. credlen = %d\n", credlen);
      pki_info.enrollment_key = (uint8_t *)cred;
      pki_info.enrollment_key_len = credlen;
      break;


    default:
      LOG_ERR("Error, unknown or unsupported setting: %i\n", type);
      return -1;
  }


  return res;
}

int tls_credential_get(enum tls_credential_type type, void *cred, uint16_t *credlen)
{
  switch (type) {

    case TLS_CREDENTIAL_CA_CERTIFICATE:
      LOG_DBG("GET TLS_CREDENTIAL_CA_CERTIFICATE");
      //x509_print_certificate(conn.dtls.pki_info.ca_cert);
      //x509_certificate *tmp_cert = pki_info.ca_cert; //internal_get_signing_cert(sock); //pki_info.ca_cert;
      memcpy(cred, pki_info.ca_cert, sizeof(x509_certificate)); //pki_info.ca_cert;
      //cred = internal_get_signing_cert(sock);

     break;

    case TLS_CREDENTIAL_FACTORY_CERTIFICATE:
      LOG_ERR("TODO\n");
    break;

    case TLS_CREDENTIAL_FACTORY_KEY:
      LOG_ERR("TODO\n");
    break;

    case TLS_CREDENTIAL_ENROLLMENT_KEY:
      LOG_ERR("TODO\n");
    break;


    default:
      LOG_ERR("Error, unknown or unsupported setting: %i\n", type);
      return -1;
  }


  return 1;
}



/*---------------------------------------------------------------------------*/
