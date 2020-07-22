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

#include <coap2/coap.h>
#include <mbedtls/x509_crt.h>

#include "est-client.h"
#include "client.h"
#include "dtls-settings.h"
#include "est.h"
#include "other-ecc.h"
#include "est-x509.h"

#include "../util/log.h"
#define LOG_MODULE "est-client"
#ifdef LOG_CONF_LEVEL_EST_CLIENT
#define LOG_LEVEL LOG_CONF_LEVEL_EST_CLIENT
#else
#define LOG_LEVEL LOG_LEVEL_DBG
#endif


static unsigned char ROOT_CONF_CA[] = "MIIBczCCARmgAwIBAgIJAM2dR7gJjlllMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC1JGQyB0ZXN0IENBMB4XDTIwMDIxOTEwMzcxNVoXDTIyMDIxODEwMzcxNVowFjEUMBIGA1UEAwwLUkZDIHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuTNsB9hTe/HEhKF/cf1xtHULJVkfwYboAgN9niGeEXummn9SJMUna49OxVBbXUyw4cVK4Cw3z4a9AipXTBx5Yo1AwTjAdBgNVHQ4EFgQUvAQzwQ3fzU8+ltBGwNdu6qGBzZ4wHwYDVR0jBBgwFoAUvAQzwQ3fzU8+ltBGwNdu6qGBzZ4wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAqYQGzIRdffBrhU666iuI5jQnUVBJwCmGCaIQkGquoFMCIBeqMznbEtLEDUHJIUiJFFrJM96pbE3xFn3jbfQ1OUte";

static enum est_client_state client_state;

int
append_callback(uint8_t *data, size_t len) {

	LOG_DBG("append_to_output, len = %d\n", (int)len);
	int res;
	switch(client_state) {
	case EST_HAS_SENT_CA:
		LOG_DBG("Process cacerts response\n");
		res = est_process_cacerts_response(data, len, NULL, NULL);
		if(-1 < res) {
			client_state = EST_CA_DONE;
			LOG_DBG("Cacerts DONE\n");
		} else {
			LOG_ERR("Cacerts error\n");
		}
		break;
	case EST_HAS_SENT_SEN:
		LOG_DBG("Process enroll response\n");
		res = est_process_enroll_response(data, len, NULL, NULL);
		if(-1 < res) {
			client_state = EST_SEN_DONE;
			LOG_DBG("Enroll DONE\n");
		} else {
			LOG_ERR("Enroll error\n");
		}
		break;
	default:
		LOG_ERR("Illegal state: %d\n", client_state);
		res = -1;
		break;
	}


	//payload->s = (unsigned char *)coap_malloc(total_length_to_send);
	//payload->length = total_length_to_send;
	//mempcy(payload->s, client_buffer);


	//size_t written;

	//  if (!file) {
	//    if (!output_file.s || (output_file.length && output_file.s[0] == '-'))
	//      file = stdout;
	//    else {
	//      if (!(file = fopen((char *)output_file.s, "w"))) {
	//        perror("fopen");
	//        return -1;
	//      }
	//    }
	//  }
	//
	//  do {
	//    written = fwrite(data, 1, len, file);
	//    len -= written;
	//    data += written;
	//  } while ( written && len );
	//  fflush(file);
	//
	//  return 0;
	return res;
}

int local_setsockopt(int level, int optname, void *optval, uint16_t optlen) {
	return tls_credential_add(optname, optval, optlen);
}

int local_getsockopt(int level, int optname, void *optval, uint16_t *optlen) {
	tls_credential_get(optname, &optval, optlen);
	printf("\n1.5\n");
	return 1;
}

void init_all() {
	new_ecc_init();
	x509_set_ctime(0);
}

int
main(int argc, char **argv) {

	LOG_DBG("Starting EST client.\nWill enroll using:\nFactory cert at %s,\nCA cert at %s and\nHardcoded client id: %x:%x:%x:%x...\n", FACTORY_CERT_PATH, CA_CERT_PATH, client_mac_id[0],client_mac_id[1],client_mac_id[2],client_mac_id[3]);
	int ret = local_setsockopt(SOL_TLS_CREDENTIALS, TLS_CREDENTIAL_INITIAL_TRUSTSTORE, ROOT_CONF_CA, sizeof(ROOT_CONF_CA));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_CREDENTIAL_INITIAL_TRUSTSTORE option");
	}
	init_all();
	set_pki_data(FACTORY_CERT_PATH, CA_CERT_PATH, NULL);
	set_coap_callbacks(append_callback);
	//est_set_socket_callbacks(&local_setsockopt, &local_getsockopt);
	/*
	 * Prepare simple cacerts request
	 */
	//#define COAP_CONTENT_FORMAT_PKCS10 286
	//  set_content_type(COAP_CONTENT_FORMAT_PKCS10, COAP_OPTION_CONTENT_TYPE);
	LOG_INFO("Prepare cacerts request\n");
#define COAP_CONTENT_FORMAT_CRTS 280
	set_content_type(0, COAP_CONTENT_FORMAT_CRTS, COAP_OPTION_CONTENT_TYPE);
	set_coap_target("coaps://[localhost]/crts", COAP_GET);
	client_state = EST_HAS_SENT_CA;
	perform_request(NULL, NULL);

	LOG_INFO("Prepare enroll request\n");
	client_coap_cleanup(0, NULL, NULL);

	/*
	 * Prepare simple enroll request
	 */
#define COAP_CONTENT_FORMAT_PKCS10 286
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
	client_coap_cleanup(1, ctx, session);
	return 1;
}
