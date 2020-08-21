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

#ifndef EST_USER_H_
#define EST_USER_H_

//#define NETSTACK_CONF_MAC nullmac_driver
//#define MAC_CONF_WITH_NULLMAC 1
//#define MAC_CONF_WITH_TSCH 1

//#define LOG_CONF_LEVEL_MAC LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_RPL LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_FRAMER LOG_LEVEL_DBG
//
//#define LOG_CONF_LEVEL_SOCKET LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_COAP LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_DTLS LOG_DEBUG
#define LOG_CONF_LEVEL_COAP LOG_DEBUG
//#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_DBG

/*
 * Platform setup
 */

#define COAP_EPOLL_SUPPORT 1
#define WORDS_32_BITS 1
void set_coap_callbacks(int(*append_callback)(uint8_t *data, size_t len));

void set_content_type(int hard, uint16_t value, uint16_t key);
int set_coap_payload(unsigned char *data, int len);
int set_coap_target(char *path, int method);
int set_pki_data(char *factory_cert_file,char *factory_key, char *r_ca_file, char *i_ca_file);
int perform_request(coap_context_t *ctx, coap_session_t *session); //, int argc, char **argv);
void client_coap_cleanup(int all, coap_context_t *ctx, coap_session_t *session);


#endif /* PROJECT_CONF_H_ */
