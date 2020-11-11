/*
 * Copyright (c) 2015, SICS.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */
/**
 * \file
 *    EST client functions
 * \author
 */

#ifndef EST_CLIENT_H
#define EST_CLIENT_H

/*
 * EST path info
 */
#define CRTS_PATH "crts"
#define SEN_PATH "sen"
#define SKG_PATH "skg"

static uint8_t client_mac_id[] = { 0xe,0x9,0xa,0xc,0x8,0x7,0xb,0x1 }; //TODO read from HW


#define COAP_CONTENT_FORMAT_CRTS 280
#define COAP_CONTENT_FORMAT_PKCS10 286
#define COAP_CONTENT_FORMAT_CBOREN 12001

#define COAP_TEST_CONTENT_FORMAT_FOR_SEN COAP_CONTENT_FORMAT_PKCS10
/*
 * Settings we might need to trim to smallest possible
 */
#define TRUSTSTORE_PARSE_BUFFER_SIZE 1024


enum est_client_state {
  EST_WAITING_FOR_CONNECTION,
  EST_READY,
  EST_HAS_SENT_CA,
  EST_CA_DONE,
  EST_HAS_SENT_SEN,
  EST_SEN_DONE,
};

typedef enum {
  COAP_GET = 1,
  COAP_POST,
  COAP_PUT,
  COAP_DELETE
} coap_method_t;


#endif /* EST_CLIENT_H */