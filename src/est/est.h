/*
 * Copyright (c) 2015, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *          Functions for main est operations

 * \author
 *         Rúnar Már Magnússon <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#ifndef EST_H_
#define EST_H_

//#include "../est/est-x509.h"
#include "stdint.h"

#if 0 < WITH_COMPRESSION
#include "cbor.h"
#include "cn-cbor.h"
#endif

/* Server default, override as needed */
#ifdef EST_SERVER_CONF_IPV6
#define EST_SERVER_IPV6 EST_SERVER_CONF_IPV6
#else
#define EST_SERVER_IPV6 "fd02::1"
#endif

#ifndef EST_CLIENT_BUFFER_LENGTH
#define EST_CLIENT_BUFFER_LENGTH 1024
#endif

/*
 * START copied from other contiki files
 */
#define EST_WITH_ECC 1
#define UIP_802154_LONGADDR_LEN  8
//#define LLADDR
//extern uint8_t uip_lladdr[]; // = { 0xe,0x9,0xa,0xc,0x8,0x7,0xb,0x1 };

//from bigint:
//#define WORDS_32_BITS 1
//typedef uint32_t u_word;
//typedef uint64_t u_doubleword;
//typedef uint16_t u_byte;
//#define BIGINT_WORD_BITS 32
//#define WORD_LEN_BYTES (BIGINT_WORD_BITS / 8) /**<-- Length of a word in bytes */

/*
 * END copied from other contiki files
 */



//#if (EST_DEBUG) & EST_DEBUG_EST
//#define EST_DBG(...) EST_DEBUG_PRINT(__VA_ARGS__)
//#else
//#define EST_DBG(...)
//#endif

#define CA_BUFFER_SIZE 1024
#define CERT_BUFFER_SIZE 512

#define EST_CERT_IS_NOT_CA 0
#define EST_CERT_IS_CA 1

//#if !EST_WITH_COFFEE
//typedef struct est_session_data {
//  uint8_t ca_buffer[CA_BUFFER_SIZE];
//  uint8_t cert_buffer[CERT_BUFFER_SIZE];
//  x509_certificate *ca_head;
//  x509_certificate *cert_head;
//  x509_key_context key_ctx;
//  uint8_t has_key;
//} est_session_data;
//
///**
// * Zero initializes the EST session data
// * @param session_data the EST session data to initialize
// */
//void est_session_init(est_session_data *session_data);
//#endif

/**
 * Function processes cacerts response that is in the buffer
 * @param buffer the buffer with the response
 * @param buf_len the length of the buffer
 * @return 0 if successful, -1 otherwise
 */
int est_process_cacerts_response(uint8_t *buffer, uint16_t buf_len, unsigned char *path, uint8_t *result_buffer);

/**
 * Function processes enroll response that is in the buffer
 * @param buffer the buffer with the response
 * @param buf_len the length of the buffer
 * @return 0 if successful, -1 otherwise
 */
int est_process_enroll_response(uint8_t *buffer, uint16_t buf_len, unsigned char *path, uint8_t *result_buffer);

/**
 * Function creates enroll request into the buffer
 * @param buffer the buffer to store the request in
 * @param buf_len the length of the buffer
 * @return length of the request if successful, 0 otherwise
 */
uint16_t est_create_enroll_request(uint8_t *buffer, uint16_t buf_len); //, int is_skg_request);

void est_set_socket_callbacks(int (*setsockopt)(int level, int optname,
        void *optval, uint16_t optlen),
    int (*getsockopt)(int level, int optname,
         void *optval, uint16_t *optlen));

#endif /* EST_H_ */
