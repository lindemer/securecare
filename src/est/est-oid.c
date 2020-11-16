/*
 * Copyright (c) 2015, Swedish Institute of Computer Science
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
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *          Helper functions to work with ASN.1 encoded OIDs
 * \author
 *         Rúnar Már Magnússon  <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */
#include "est-oid.h"

#include "stdio.h"

#if STANDALONE_VERSION
#include "util/standalone_log.h"
#define LOG_MODULE "oid"
#ifdef LOG_CONF_LEVEL_EST_ASN1
#define LOG_LEVEL LOG_CONF_LEVEL_EST_ASN1
#else
#define LOG_LEVEL LOG_LEVEL_ERR //DBG
#endif
#else
#include "util/nrf_log_wrapper.h"
#endif

//#if LOG_LEVEL == LOG_LEVEL_DBG
//#include "socket-dtls.h"
//#define EST_DEBUG_OID 1
//#define EST_HEXDUMP hdumps
//#endif


/*---------------------------------------------------------------------------*/
int
oid_cmp(char *str_oid, uint8_t *oid_buf, uint16_t oid_len)
{
  int i = 0;

#if EST_DEBUG_OID
  /* Print out both OIDs */
  LOG_DBG("\noid_cmp - Comparing: \nstr_oid (%d):\t ", (int)OID_LENGTH(str_oid));
  EST_HEXDUMP((uint8_t *)str_oid, OID_LENGTH(str_oid));
  LOG_DBG("oid_buf (%d):\t", (int)oid_len);
  EST_HEXDUMP(oid_buf, oid_len);
  LOG_DBG("\n");
#endif

  if(OID_LENGTH(str_oid) != oid_len) {
#if EST_DEBUG_OID
    LOG_DBG("oid_cmp - str_oid and oid_buf lengths don't match\n");
#endif
    return -1;
  } else {
    for(i = 0; i < oid_len; i++) {
      if(((uint8_t)str_oid[i]) != oid_buf[i]) {
#if EST_DEBUG_OID
        LOG_DBG("oid_cmp - str_oid is not the same as oid_buf\n");
#endif

        return -1;
      }
    }
  }

  return 0;
}
/*---------------------------------------------------------------------------*/
