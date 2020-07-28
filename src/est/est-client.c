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

/*
 * libcoap
 */
#include "client.h"
/*
 * EST
 */
#include "est-client.h"
#include "est.h"
#include "est-x509.h"

#include "log.h"
#include "mbedtls-wrapper.h"
#define LOG_MODULE "est-client"
#ifdef LOG_CONF_LEVEL_EST_CLIENT
#define LOG_LEVEL LOG_CONF_LEVEL_EST_CLIENT
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif

unsigned char enrolled_cert_buffer[512];

static enum est_client_state client_state;

int append_callback(uint8_t *data, size_t len) {

	LOG_DBG("append_to_output, len = %d\n", (int)len);
	int res;
	int result_len;
	switch(client_state) {
	case EST_HAS_SENT_CA:
		LOG_DBG("Process cacerts response\n");
		res = est_process_cacerts_response(data, len, NULL, enrolled_cert_buffer, &result_len);
		if(-1 < res) {
			client_state = EST_CA_DONE;
			LOG_DBG("Cacerts DONE\n");
		} else {
			LOG_ERR("Cacerts error\n");
		}
		break;
	case EST_HAS_SENT_SEN:
		LOG_DBG("Process enroll response\n");
		res = est_process_enroll_response(data, len, NULL, enrolled_cert_buffer, &result_len);
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
	est_dtls_wrapper_init(ca_path);
	x509_set_ctime(0);
}

int
main(int argc, char **argv) {

	LOG_DBG("Starting EST client.\nWill enroll using:\nFactory cert at %s,\nCA cert at %s and\nHardcoded client id: %x:%x:%x:%x...\n", FACTORY_CERT_PATH, CA_CERT_PATH, client_mac_id[0],client_mac_id[1],client_mac_id[2],client_mac_id[3]);

	init_all(CA_CERT_PATH);
	set_pki_data(FACTORY_CERT_PATH, CA_CERT_PATH, NULL);
	set_coap_callbacks(append_callback);

	/*
	 * Prepare simple cacerts request
	 */
	LOG_INFO("Prepare cacerts request\n");

	set_content_type(0, COAP_CONTENT_FORMAT_CRTS, COAP_OPTION_CONTENT_TYPE);
	set_coap_target("coaps://[localhost]/crts", COAP_GET);
	client_state = EST_HAS_SENT_CA;
	perform_request(NULL, NULL);

	LOG_INFO("Prepare enroll request\n");
	client_coap_cleanup(0, NULL, NULL);

	/*
	 * Prepare simple enroll request
	 */
	set_content_type(1, COAP_CONTENT_FORMAT_PKCS10, COAP_OPTION_CONTENT_TYPE);
	uint8_t client_buffer[512];
	int total_length_to_send = est_create_enroll_request(client_buffer, 512);

	set_coap_payload(client_buffer, total_length_to_send);
	set_coap_target("coaps://[localhost]/sen", COAP_POST);


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
