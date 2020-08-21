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

/*
 * Standard includes
 */
#include "mbedtls-wrapper.h"

#include <errno.h>
#include <stdio.h> /* Debug / for printf */
#include <string.h>
#include <unistd.h> // for sleep, might delete

/*
 * MBED includes
 */
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h> //at least for now
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/*
 * Local includes
 */
#include "est-base64.h"
#include "project-conf.h"
//#include "est-client.h"

#include "log.h"
#define LOG_MODULE "dtls-wrapper"
#define LOG_LEVEL LOG_LEVEL_DBG

//static dtls_context_t *dtls_context = NULL; //TODO, maybe link with existing dtls-struct

static struct pki_info_t pki_info;
static struct libcoap_info_t libcoap_info;

/*
 * Local/internal functions
 */
int generate_ecc_key(mbedtls_pk_context *);
int get_enrollment_key(unsigned char *buf_x, unsigned char *buf_y, unsigned char *buf_d);
int test_set_key(mbedtls_ecp_keypair *ecp, const char *X, const char *Y, const char *d);
int x509_crt_parse_file( mbedtls_x509_crt *chain, unsigned char *chain_buffer, size_t *ts_len, const char *path);

/*
 * Initialize keys. Load ca-cert(s) and create key contexts for signing
 * and verifying during est operations
 */
int est_dtls_wrapper_init(const char* ca_certs_path) {

  LOG_DBG("Initialize crypto settings\n");
  pki_info.mbedtls_truststore_certs = malloc(sizeof(mbedtls_x509_crt));
  mbedtls_x509_crt_init(pki_info.mbedtls_truststore_certs);
  pki_info.fts_cert_buf = malloc(TRUSTSTORE_PARSE_BUFFER_SIZE);

  size_t ts_len;

  int ret;

  if(ca_certs_path) {
    ret = x509_crt_parse_file(pki_info.mbedtls_truststore_certs, pki_info.fts_cert_buf, &ts_len, ca_certs_path);

    if(ret < 0) {
      LOG_ERR("Parsing of CA certs for truststore failed\n");
      return ret;
    }

    ret = tls_credential_add(TLS_CREDENTIAL_INITIAL_TRUSTSTORE, pki_info.fts_cert_buf, ts_len);

  } else {
    uint8_t ca_cert[] = CA_CERT_STRING;
    int len = sizeof(ca_cert);
    memcpy(pki_info.fts_cert_buf, ca_cert, len);
    ret = tls_credential_add(TLS_CREDENTIAL_INITIAL_TRUSTSTORE, pki_info.fts_cert_buf, len);
  }

  if(ret < 0) {
    LOG_ERR("Storing of CA certs for truststore failed\n");
    return ret;
  }

  pki_info.enrollment_key_ctx = malloc(sizeof(mbedtls_pk_context));
  pki_info.verify_key_ctx = malloc(sizeof(mbedtls_pk_context));

  ret = generate_ecc_key(pki_info.enrollment_key_ctx);
  //  LOG_INFO("Initialize hardcoded test key that fails\n");
  //  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
  //  const char *X = "BC86738CF3B6A56A027DD30EB63DFDDB9C16593D1648D873F94C19461919C965";
  //  const char *Y = "856123050F418C3891D4D3D4E41B87AB542EB73488D52595E3AA17483BB651C3";
  //  const char *d = "E1424BDC2019F1B31791D9D26E0A94DAC78655AD30942C0FF8E4A9FAECC6421C";
  //  ret = test_set_key(ecp, X, Y, d);
  //	if(ret < 0) {
  //		return ret;
  //	}

  //	  LOG_INFO("Initialize hardcoded test key that succeeds\n");
  //	  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
  //	  const char *X = "1B491D3ECDA37EB03E58F2EA4BFE83925017F920A05F8A8420F9CB9FFB8C482B";
  //	  const char *Y = "DFC37AC510FB4E10E588CA4166AF424771906B1A78B7F22E2B8AE2AE38533105";
  //	  const char *d = "7FCD8DBA6160814A471FCE6273880F709BE635DE847576105B7B99C8AF6F2449";
  //	  ret = test_set_key(ecp, X, Y, d);
  //	  if(ret < 0) {
  //	    return ret;
  //	  }

  ret = generate_ecc_key(pki_info.verify_key_ctx);
  if(ret < 0) {
    return ret;
  }

  return 0;
}
int est_dtls_wrapper_free() {
  mbedtls_pk_free(pki_info.enrollment_key_ctx);
  mbedtls_pk_free(pki_info.verify_key_ctx);
  return 0;
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/

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

/*---------------------------------------------------------------------------*/

int tls_credential_add(enum tls_credential_type type, void *cred, uint16_t credlen)
{
  int res = 0;
  switch (type) {

  case TLS_CREDENTIAL_INITIAL_TRUSTSTORE:
    LOG_DBG("TLS_CREDENTIAL_INITIAL_TRUSTSTORE // Warning, will mess up original data buffer. credlen = %d\n", credlen);
    credlen = est_base64_decode_block_inplace((char *)cred, credlen);
    pki_info.ca_cert = x509_decode_certificate((uint8_t **)&cred, (cred+credlen));
    //x509_print_certificate(pki_info.ca_cert);
    //TODO, test chain of certs
    break;

  case TLS_CREDENTIAL_ENROLLED_TRUSTSTORE:
    LOG_DBG("TLS_CREDENTIAL_ENROLLED_TRUSTSTORE - setting pointer only. credlen = %d\n", credlen);
    pki_info.ets_cert_buf = (unsigned char*)cred;
    pki_info.ets_cert_buf_len = credlen;
    break;

  case TLS_CREDENTIAL_ENROLLED_CERTIFICATE:
    LOG_DBG("TLS_CREDENTIAL_ENROLLED_CERTIFICATE - store pointer to byte array\n");
    pki_info.enrolled_cert_buf = (unsigned char*)cred;
    //		pki_info.enrolled_cert_buf = (unsigned char*)cred;
    //		pki_info.enrolled_cert_buf_len = credlen;
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
    LOG_DBG("TLS_CREDENTIAL_FACTORY_KEY. TODO?\n");
    //		LOG_DBG("TLS_CREDENTIAL_FACTORY_KEY. Currently stored as reference. credlen = %d\n", credlen);
    //		pki_info.factory_key = (uint8_t *)cred;
    //		pki_info.factory_key_len = credlen;
    break;

  case TLS_CREDENTIAL_ENROLLMENT_KEY:
    LOG_ERR("No setter for ENROLLMENT_KEY. Use TLS_CREDENTIAL_ENROLLED_CERTIFICATE to store certificate\n");
    return -1;

  default:
    LOG_ERR("Error, unknown or unsupported setting: %i\n", type);
    return -1;
  }


  return res;
}
/*---------------------------------------------------------------------------*/

int tls_credential_get(enum tls_credential_type type, void *cred, uint16_t *credlen)
{
  switch (type) {

  case TLS_CREDENTIAL_CA_CERTIFICATE:
    LOG_DBG("GET TLS_CREDENTIAL_CA_CERTIFICATE\n");
    memcpy(cred, pki_info.ca_cert, sizeof(x509_certificate)); //pki_info.ca_cert;
    *credlen = sizeof(x509_certificate);
    //x509_print_certificate(pki_info.ca_cert);
    cred = pki_info.ca_cert;
    break;

  case TLS_CREDENTIAL_FACTORY_CERTIFICATE:
    LOG_ERR("TODO\n");
    break;

  case TLS_CREDENTIAL_FACTORY_KEY:
    LOG_ERR("TODO\n");
    break;

  case TLS_CREDENTIAL_ENROLLMENT_KEY:
    if(pki_info.enrollment_key_ctx != NULL) {
      LOG_DBG("GET TLS_CREDENTIAL_ENROLLMENT_KEYS\n");
      return get_enrollment_key(((x509_key_context*)cred)->pub_x, ((x509_key_context*)cred)->pub_y, ((x509_key_context*)cred)->priv);

    }
    LOG_WARN("TLS_CREDENTIAL_ENROLLMENT_KEYS not set");
    return -1;


    break;


  default:
    LOG_ERR("Error, unknown or unsupported setting: %i\n", type);
    return -1;
  }
  return 1;
}

int generate_enrollment_keys(x509_key_context *key_ctx) {

  pki_info.enrollment_key_ctx = malloc(sizeof(mbedtls_pk_context));
  int ret = generate_ecc_key(pki_info.enrollment_key_ctx);
  if(ret < 0) {
    return ret;
  }
  uint16_t credlen;
  return tls_credential_get(TLS_CREDENTIAL_ENROLLMENT_KEY, &key_ctx, &credlen);
}

/*---------------------------------------------------------------------------*/
/*
 * Internal helper function
 */
/*---------------------------------------------------------------------------*/

int x509_crt_parse_file( mbedtls_x509_crt *chain, unsigned char *chain_buffer, size_t *ts_len, const char *path) {
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  size_t n;
  unsigned char *buf;

  if((ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0) {
    return ret;
  }

  *ts_len = n - 2*PEM_HEADER_AND_FOOTER_LEN;

  memcpy(chain_buffer, buf+PEM_HEADER_AND_FOOTER_LEN, *ts_len); //*ts_len-header-footer
  ret = mbedtls_x509_crt_parse( chain, buf, n);

  return( ret );
}

/*---------------------------------------------------------------------------*/
/*
 * Internal, for key-gen, if desired
 */
/*---------------------------------------------------------------------------*/

#define DEV_RANDOM_THRESHOLD        32
int dev_random_entropy_poll( void *data, unsigned char *output,
    size_t len, size_t *olen )
{
  FILE *file;
  size_t ret, left = len;
  unsigned char *p = output;
  ((void) data);

  *olen = 0;

  file = fopen( "/dev/random", "rb" );
  if( file == NULL )
    return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

  while( left > 0 )
  {
    /* /dev/random can return much less than requested. If so, try again */
    ret = fread( p, 1, left, file );
    if( ret == 0 && ferror( file ) )
    {
      fclose( file );
      return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    p += ret;
    left -= ret;
    sleep(1);
  }
  fclose( file );
  *olen = len;

  return( 0 );
}

/*---------------------------------------------------------------------------*/


int generate_ecc_key(mbedtls_pk_context *target_key_ctx) {

  int ret = 1;
  int exit_code = EXIT_FAILURE;

  mbedtls_mpi Q;
  mbedtls_entropy_context entropy;
  const char *pers = "gen_key_seed";
  mbedtls_ctr_drbg_context ctr_drbg;
  /*
   * Init stuff
   */
  mbedtls_mpi_init( &Q );

  mbedtls_pk_init(target_key_ctx);
  mbedtls_ctr_drbg_init( &ctr_drbg );


  int type = MBEDTLS_PK_ECKEY;
  int ec_curve = MBEDTLS_ECP_DP_SECP256R1;
  int use_dev_random = DFL_USE_DEV_RANDOM;

  fflush( stdout );

  mbedtls_entropy_init( &entropy );

  /*
   * Probably not to be used
   */
  if(use_dev_random)
  {
    LOG_DBG("Key generation using /dev/random: expensive!\n");
    fflush( stdout );

    if( ( ret = mbedtls_entropy_add_source( &entropy, dev_random_entropy_poll,
        NULL, DEV_RANDOM_THRESHOLD,
        MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )  {

      LOG_ERR("Key generation failed, mbedtls_entropy_add_source returned -0x%04x\n", (unsigned int) -ret );
      goto exit; //keep for adding clean-up
    }
  }

  if((ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
      (const unsigned char *) pers,
      strlen(pers))) != 0 ) {

    LOG_ERR("Key generation failed, mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret );
    goto exit; //keep for adding clean-up
  }

  LOG_DBG("Key context generation\n");
  fflush( stdout );

  if((ret = mbedtls_pk_setup(target_key_ctx,
      mbedtls_pk_info_from_type( (mbedtls_pk_type_t) type ) ) ) != 0 ) {
    LOG_ERR("Key generation failed for target_key_ctx, mbedtls_pk_setup returned -0x%04x", (unsigned int) -ret );
    goto exit; //keep for adding clean-up
  }

  ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) ec_curve,
      mbedtls_pk_ec(*target_key_ctx),
      mbedtls_ctr_drbg_random, &ctr_drbg );
  if(ret != 0) {
    LOG_ERR("Key generation failed for target_key_ctx, mbedtls_ecp_gen_key returned -0x%04x", (unsigned int) -ret );
    goto exit;
  }

  exit_code = EXIT_SUCCESS;

  exit:

  if( exit_code != EXIT_SUCCESS )
  {
#ifdef MBEDTLS_ERROR_C
    char buf[256];
    memset( buf, 0, sizeof( buf ) );
    mbedtls_strerror( ret, buf, sizeof( buf ) );
    LOG_ERR( " - %s\n", buf );
#endif
  }
  mbedtls_mpi_free( &Q );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );

  return 1;
}

/*
 * Assuming
 * key_size = 32
 */
int get_enrollment_key(unsigned char *buf_x, unsigned char *buf_y, unsigned char *buf_d) {
  const int key_size = ECC_DEFAULT_KEY_LEN;
  if(NULL==pki_info.enrollment_key_ctx){
    return -1;
  }
  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
  int ret = mbedtls_mpi_write_binary(&ecp->Q.X, buf_x, key_size);
  if(ret<0) return ret;
  ret = mbedtls_mpi_write_binary(&ecp->Q.Y, buf_y, key_size);
  if(ret<0) return ret;
  return mbedtls_mpi_write_binary(&ecp->d, buf_d, key_size);
}


/**
 * This is assuming the pki_info.enrollment_key_ctx is properly initialized
 */
int create_ecc_signature(const unsigned char *buffer, size_t data_len, unsigned char *r_buf, const size_t r_len,
    unsigned char *s_buf, const size_t s_len) {

  printf("1\n");
  const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  unsigned char *md = malloc(mdinfo->size);
  //Calculate the message digest/hash256 for the data
  int  st = mbedtls_md(mdinfo, buffer, data_len, md);
  if(st < 0) {
    LOG_ERR("Hashing error, abort\n");
    return st;
  }
  printf("2: st = %d, mdinfo->size = %d\n", st, mdinfo->size);

  //retrieve the previously stored enrollment keys
  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
  printf("3\n");
  //Create a signature for the hash of the data
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  printf("4\n");
  st = mbedtls_ecdsa_sign_det(&ecp->grp, &r, &s, &ecp->d, md, mdinfo->size, MBEDTLS_MD_SHA256);
  printf("5\n");
#if 1 //DEBUG_MBED_WRAPPER
  printf("Input data: %u \n", (unsigned int)data_len);
  hdumps(buffer, data_len);
  printf("\n");
  printf("HASH for signing:\n");
  hdumps(md, 32);
  printf("\n");

  mbedtls_mpi_write_file( "X, from key:   ", &ecp->Q.X, 16, NULL );
  mbedtls_mpi_write_file( "Y, from key:   ", &ecp->Q.Y, 16, NULL );
  mbedtls_mpi_write_file( "d, from key:   ", &ecp->d, 16, NULL );
  mbedtls_mpi_write_file( "r, generated:   ", &r, 16, NULL );
  mbedtls_mpi_write_file( "s, generated:   ", &s, 16, NULL );
#endif

  mbedtls_mpi_write_binary(&r, r_buf, r_len);
  mbedtls_mpi_write_binary(&s, s_buf, s_len);

  free(md);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  if (st != 0) {
    return -1;
  }
  return 1;
}


/**
 * This is assuming the pki_info.verify_key_ctx is properly initialize
 */
int verify_ecc_signature(x509_key_context *pk_ctx, const unsigned char *buffer, size_t data_len, const unsigned char *r_buf, const size_t r_len, const unsigned char *s_buf, const size_t s_len) {

  /*
   * Replacing the ecc part of x509_verify_ecdsa_signature
   */
  mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.verify_key_ctx);
  mbedtls_mpi_read_binary(&ecp->Q.X, pk_ctx->pub_x, ECC_DEFAULT_KEY_LEN);
  mbedtls_mpi_read_binary(&ecp->Q.Y, pk_ctx->pub_y, ECC_DEFAULT_KEY_LEN);

  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  mbedtls_mpi_read_binary(&r, r_buf, r_len);
  mbedtls_mpi_read_binary(&s, s_buf, s_len);

  const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  unsigned char *md = malloc(mdinfo->size);
  //Hash
  mbedtls_md(mdinfo, buffer, data_len, md);

#if 1 //DEBUG_MBED_WRAPPER
  printf("Data to check: %u \n", (unsigned int)data_len);
  hdumps(buffer, data_len);
  printf("\n");
  printf("HASH of signing:\n");
  hdumps(md, 32);
  printf("\n");

  mbedtls_mpi_write_file( "X, from key:   ", &ecp->Q.X, 16, NULL );
  mbedtls_mpi_write_file( "Y, from key:   ", &ecp->Q.Y, 16, NULL );
  //mbedtls_mpi_write_file( "d, from key:   ", &ecp->d, 16, NULL );
  mbedtls_mpi_write_file( "r, to check:   ", &r, 16, NULL );
  mbedtls_mpi_write_file( "s, to check:   ", &s, 16, NULL );
  printf("r-len & s-len: %u %u\n", (unsigned int)r_len, (unsigned int)s_len);
#endif

  //Verify the signature
  int st = mbedtls_ecdsa_verify(&ecp->grp, md, mdinfo->size, &ecp->Q, &r, &s);

  //Cleanup
  free(md);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  if (st != 0) {
    return -1;
  }

  return 1;

}


/*
 * Leftover test code
 */
//	LOG_INFO("Initialize hardcoded test key\n");
//	mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pki_info.enrollment_key_ctx);
//	const char *X = "BC86738CF3B6A56A027DD30EB63DFDDB9C16593D1648D873F94C19461919C965";
//	const char *Y = "856123050F418C3891D4D3D4E41B87AB542EB73488D52595E3AA17483BB651C3";
//	const char *d = "E1424BDC2019F1B31791D9D26E0A94DAC78655AD30942C0FF8E4A9FAECC6421C";
//	test_set_key(ecp, X, Y, d);

/*
 * Internal util
 */
int test_set_key(mbedtls_ecp_keypair *ecp, const char *X, const char *Y, const char *d) {

  int ret = 0;

  ret = mbedtls_mpi_read_string(&ecp->Q.X, 16, X);
  if(ret < 0) return ret;
  ret = mbedtls_mpi_read_string(&ecp->Q.Y, 16, Y);
  if(ret < 0) return ret;
  ret = mbedtls_mpi_read_string(&ecp->d, 16, d);
  if(ret < 0) return ret;
  //ecp->d = NULL;
  mbedtls_mpi_write_file( "X_Q, loaded:   ", &ecp->Q.X, 16, NULL );
  mbedtls_mpi_write_file( "Y_Q, loaded:   ", &ecp->Q.Y, 16, NULL );

  return 0;
}
