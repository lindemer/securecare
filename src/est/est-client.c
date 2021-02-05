/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap-client -- simple CoAP client
 *
 * Copyright (C) 2010--2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/*
 * libcoap
 */
#include <coap2/coap.h>
/*
 * mbedtls
 */
#include <mbedtls/x509_crt.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h> //at least for now
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
/*
 * libcoap
 */
#include "client.h"
/*
 * EST
 */
#include "est-client.h"
#include "est.h"
#include "est-standalone-conf.h"
#include "est-x509.h"
/*
 * EDHOC
 */
//#include "/home/ubuntu/eclipse-workspace/libcoap/examples/edhoc/LakeS2TV.h"

/*
 * settings
 */
const uint8_t client_mac_id[] = { 0xe,0x9,0xa,0xc,0x8,0x7,0xb,0x1 }; //TODO read from HW


#include "crypto-wrapper.h"
#define LOG_MODULE "est-client"
#ifdef LOG_CONF_LEVEL_EST_CLIENT
#define LOG_LEVEL LOG_CONF_LEVEL_EST_CLIENT
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif
#include "standalone_log.h"

unsigned char enrolled_ts_buffer[1024];
unsigned char enrolled_cert_buffer[512];


static enum est_client_state client_state;

int append_callback(uint8_t *data, size_t len) {

	LOG_DBG("append_to_output, len = %d\n", (int)len);
	int res;
	int result_len;
	switch(client_state) {
	case EST_HAS_SENT_CA:
		LOG_DBG("Process cacerts response: \n");
		//hdumps(data, len);
		//LOG_DBG("\n");

		res = est_process_cacerts_response(data, len, NULL, enrolled_ts_buffer, &result_len);
    LOG_DBG("enrolled_cert_buffer len: %d\n", result_len);
    hdumps(enrolled_ts_buffer, result_len);

    if(-1 < res) {

			LOG_DBG("Cacerts downloaded, store them! Len: %d\n", result_len);
			//hdumps(enrolled_ts_buffer, result_len);
			res = tls_credential_add(TLS_CREDENTIAL_ENROLLED_TRUSTSTORE, enrolled_ts_buffer, result_len);
			if(-1 < res) {
			  LOG_DBG("Cacerts DONE\n");
			  client_state = EST_CA_DONE;
			} else {
			  LOG_ERR("Cacerts store error\n");
			}

		} else {
			LOG_ERR("Cacerts error\n");
		}
		break;
	case EST_HAS_SENT_SEN:
		LOG_DBG("Process enroll response\n");
		res = est_process_enroll_response(data, len, NULL, enrolled_cert_buffer, &result_len);
		//https://github.com/bergzand/NanoCBOR
		if(-1 < res) {
			client_state = EST_SEN_DONE;
			LOG_DBG("Enroll DONE\n");
			printf("enrolled_cert_buffer, len = %d\n", result_len);
			hdumps(enrolled_cert_buffer, result_len);
		} else {
			LOG_ERR("Enroll error\n");
		}
		break;
	default:
		LOG_ERR("Illegal state: %d\n", client_state);
		res = -1;
		break;
	}
	return res;
}

int local_setsockopt(int level, int optname, void *optval, uint16_t optlen) {
	return tls_credential_add(optname, optval, optlen);
}

int local_getsockopt(int level, int optname, void *optval, uint16_t *optlen) {
	tls_credential_get(optname, &optval, optlen);
	return 1;
}

void init_all(const char* ca_path) {
	//new_ecc_init();
	est_dtls_wrapper_init(ca_path, 1);
	x509_set_ctime(0);
	/*
	 * TODO test area below
	 */



  return;

}

int
main(int argc, char **argv) {

	LOG_INFO("Starting EST client.\n");


#ifdef FACTORY_CERT_PATH
	LOG_INFO("Will enroll using:\nFactory cert at %s and\nCA cert at %s\n", FACTORY_CERT_PATH, CA_CERT_PATH);
	init_all(NULL);
	//set_pki_data(FACTORY_CERT_PATH, NULL, CA_CERT_PATH, NULL);
	set_pki_data(FACTORY_CERT_PATH, NULL, CA_CERT_PATH, NULL);
#else
	LOG_INFO("Will enroll using:\nFactory cert: %s and\nCA cert %s\n", FACTORY_CERT, INITIAL_TRUSTSTORE);
	init_all(NULL);
	set_pki_data(FACTORY_CERT, FACTORY_KEY, NULL, INITIAL_TRUSTSTORE);
#endif

	LOG_INFO("and hardcoded client id: %x:%x:%x:%x...\n", client_mac_id[0],client_mac_id[1],client_mac_id[2],client_mac_id[3]);
	set_coap_callbacks(append_callback);

//	const uint8_t factory_key[] = FACTORY_KEY; //_STRING; //'load from flash'
//	uint32_t key_len = sizeof(factory_key);
//
//  mbedtls_pk_context mPrivatePEMKey;
//  memset(&mPrivatePEMKey, 0, sizeof(mPrivatePEMKey));
//
//	int ret = mbedtls_pk_parse_key( &mPrivatePEMKey,
//	                  (const unsigned char *)factory_key, (size_t)key_len,
//	                  NULL, 0);
//
//	LOG_INFO("PEM key decoding returned %d\n", ret);
//
//  const uint8_t factory_key_string[] = {0x30,0x77,0x02,0x01,0x01,0x04,0x20,0xdc,0x66,0xb3,0x41,0x54,0x56,0xd6,0x49,0x42,0x9b,0x53,0x22,0x3d,0xf7,0x53,0x2b,0x94,0x2d,0x6b,0x0e,0x08,0x42,0xc3,0x0b,0xca,0x4c,0x0a,0xcf,0x91,0x54,0x7b,0xb2,0xa0,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0xa1,0x44,0x03,0x42,0x00,0x04,0xae,0x4c,0xdb,0x01,0xf6,0x14,0xde,0xfc,0x71,0x21,0x28,0x5f,0xdc,0x7f,0x5c,0x6d,0x1d,0x42,0xc9,0x56,0x47,0xf0,0x61,0xba,0x00,0x80,0xdf,0x67,0x88,0x67,0x84,0x5e,0xe9,0xa6,0x9f,0xd4,0x89,0x31,0x49,0xda,0xe3,0xd3,0xb1,0x54,0x16,0xd7,0x53,0x2c,0x38,0x71,0x52,0xb8,0x0b,0x0d,0xf3,0xe1,0xaf,0x40,0x8a,0x95,0xd3,0x07,0x1e,0x58};
//	//const uint8_t factory_key_string[] = {0xDC,0x66,0xB3,0x41,0x54,0x56,0xD6,0x49,0x42,0x9B,0x53,0x22,0x3D,0xF7,0x53,0x2B,0x94,0x2D,0x6B,0x0E,0x08,0x42,0xC3,0x0B,0xCA,0x4C,0x0A,0xCF,0x91,0x54,0x7B,0xB2};
//  key_len = sizeof(factory_key);
//
//  mbedtls_pk_context mPrivateDERKey;
//  memset(&mPrivateDERKey, 0, sizeof(mPrivateDERKey));
//
//
//  ret = mbedtls_pk_parse_key( &mPrivateDERKey,
//                    (const unsigned char *)factory_key_string, (size_t)key_len,
//                    NULL, 0);
//
//  LOG_INFO("DER key decoding returned %d, from key len %d\n", ret, (int)key_len);
//
//
//if(1) {
//  return -1;
//}
	/*
	 * Prepare simple cacerts request
	 */
	LOG_INFO("Prepare cacerts request\n");
	set_content_type(0, COAP_CONTENT_FORMAT_CRTS, COAP_OPTION_CONTENT_TYPE);
	set_coap_target(EST_CRTS_URL, COAP_GET);
	client_state = EST_HAS_SENT_CA;
	perform_request(NULL, NULL);
	client_coap_cleanup(0, NULL, NULL);

  /*
   * Prepare simple enroll request
   */
  set_content_type(1, COAP_TEST_CONTENT_FORMAT_FOR_SEN, COAP_OPTION_CONTENT_TYPE);
  uint8_t client_buffer[512];

#ifdef USE_CBOR_ENCODING
	LOG_INFO("Prepare cbor enroll request\n");
  int total_length_to_send = est_create_enroll_request_cbor(client_buffer, 512);
#else
	LOG_INFO("Prepare standard enroll request\n");
	int total_length_to_send = est_create_enroll_request(client_buffer, 512);
#endif





	set_coap_payload(client_buffer, total_length_to_send);
	set_coap_target(EST_SEN_URL, COAP_POST);


	coap_context_t  *ctx = malloc(sizeof(coap_context_t));
	coap_session_t *session = malloc(sizeof(coap_session_t));
	libcoap_get_setting(LIBCOAP_CONTEXT_TYPE, ctx);
	libcoap_get_setting(LIBCOAP_SESSION_TYPE, session);

	client_state = EST_HAS_SENT_SEN;
	perform_request(ctx, session);

	//perform_request(ctx, session);
	LOG_INFO("EST operations done\n");
	est_dtls_wrapper_free(); //When to do this depends of what should be done next!
	client_coap_cleanup(1, ctx, session);
	return 1;
}
