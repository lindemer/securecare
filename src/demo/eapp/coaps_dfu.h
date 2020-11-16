/**
 * Copyright (c) 2020, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 **/

#ifndef BACKGROUND_DFU_COAPS_API_H_
#define BACKGROUND_DFU_COAPS_API_H_

#include <openthread/coap.h>
#include <openthread/coap_secure.h>
#include <openthread/crypto.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/message.h>
#include <openthread/random_noncrypto.h>
#include "background_dfu_state.h"

struct background_dfu_diagnostic;

// Maximum app_scheduler event size
#define SCHED_EVENT_DATA_SIZE MAX(sizeof(nrf_dfu_request_t), APP_TIMER_SCHED_EVENT_DATA_SIZE)

// CoAP temporary buffer size
#define RECEIVE_BUFFER_LENGTH            1536
#define SEND_BUFFER_LENGTH       512

typedef struct coaps_dfu_context
{
    uint8_t                  buffer[RECEIVE_BUFFER_LENGTH]; // Last received CoAP payload.
    uint32_t                 buffer_length;         // Length of the last received CoAP payload.
    uint8_t                  payload[SEND_BUFFER_LENGTH];
    uint32_t                 payload_len;
    const char             * resource_path;         // Downloaded resource path on the remote host.
    uint8_t                  remote_addr[16];       // Remote address from which the resource is being downloaded.
    uint16_t                 remote_port;           // Remote port from which the resource is being downloaded.
    otCoapResponseHandler    handler;               // A pointer to the current response handler.
} coaps_dfu_context_t;

//extern struct coaps_dfu_context_t       m_coaps_dfu_ctx; //TODO

/** @brief Initialize DFU client.
 *
 *  @param[in] Application context for CoAP.
 *
 *  @return NRF_SUCCESS on success, otherwise an error code is returned.
 *  @param[in] do_enroll A flag to indicate if the node should perform enrollment
 */
uint32_t coaps_dfu_init(const void * p_context, background_dfu_state_t initial_state);

/** @brief Start DFU client.
 *
 *  @return NRF_SUCCESS on success, otherwise an error code is returned.
 */
uint32_t coaps_dfu_start();

// Reset DFU state.
void coaps_dfu_reset_state(void);

/** @brief Get DFU diagnostic information.
 *
 *  @param[out] p_diag a pointer to a structure where diagnostic information
 *                     will be copied.
 */
void coaps_dfu_diagnostic_get(struct background_dfu_diagnostic * p_diag);

/** @brief Handle DFU error.
 *
 *  This function can be implemented in the application to undertake application-specific action on DFU error.
 */
extern void coaps_dfu_handle_error(void);

#endif /* BACKGROUND_DFU_COAPS_API_H_ */
