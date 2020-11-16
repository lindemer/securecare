/*
 * Copyright (c) 2017, Inria.
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
 *         Mapping contiki-logs to nrf-logs
 */

#ifndef __LOG_WRAP_H__
#define __LOG_WRAP_H__

#include <stdio.h>
//#define NRF_LOG_MODULE_NAME est??
//#include "nrf_log.h"

//#include "sys/log-conf.h"
/* More compact versions of LOG macros */
//#define LOG_PRINT(...)         NRF_LOG_WARNING(...)
//#define LOG_ERR(...)           NRF_LOG_ERROR(...)
//#define LOG_WARN(...)          NRF_LOG_WARNING(...)
//#define LOG_INFO(...)          NRF_LOG_INFO(...)
//#define LOG_DBG(...)           NRF_LOG_DEBUG(...)

#define NRF_LOG_ERROR     LOG_ERR
#define NRF_LOG_WARNING   LOG_WARN
#define NRF_LOG_INFO      LOG_INFO
#define NRF_LOG_DEBUG     LOG_DBG
#define NRF_LOG_FLUSH();

#endif /* __LOG_H__ */

/** @} */
/** @} */
