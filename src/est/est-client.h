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
 *    Main EST client functions
 * \author
 *    Runar Mar Magnusson <rmma@kth.se>
 *    Tomas Thor Helgason <helgas@kth.se>
 */

#ifndef EST_CLIENT_OLD_H
#define EST_CLIENT_OLD_H

#define CRTS_PATH "crts"
#define SEN_PATH "sen"
#define SKG_PATH "skg"

static uint8_t client_mac_id[] = { 0xe,0x9,0xa,0xc,0x8,0x7,0xb,0x1 }; //TODO read from HW

#define FACTORY_CERT_PATH		"../../certs/factory_cert.pem"
#define CA_CERT_PATH		"../../certs/ca_cert.pem"

//#define TRUSTSTORE_PATH	"../../certs/truststore/"
//#include "est-debug.h.ignore"
//#include "er-coap.h"
//#include "../est/est-dtls.h"


/**
 * Print CA certificates
 */
//void est_client_print_cacerts(void);

/**
 * Print enrolled client certificate
 */
//void est_client_print_cert(void);

/**
 * Set client callbacks
 */

enum est_client_state {
  EST_WAITING_FOR_CONNECTION,
  EST_READY,
  EST_HAS_SENT_CA,
  EST_CA_DONE,
  EST_HAS_SENT_SEN,
  EST_SEN_DONE,
};


#endif /* EST_CLIENT_H */
