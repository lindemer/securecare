/**
 * Copyright (c) 2017 - 2020, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/** @file
 *
 * @defgroup background_dfu_coap_transport background_dfu_coap.c
 * @{
 * @ingroup background_dfu
 * @brief Background DFU CoAP transport implementation.
 *
 */

#include "background_dfu_transport.h"
#include "coap_dfu.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "sdk_config.h"
#include "boards.h"
#include "app_util.h"
#include "app_timer.h"
#include "app_scheduler.h"
#include "nrf_delay.h"
#include "nrf_error.h"
#include "nrf_log_ctrl.h"
#include "nrf_dfu_settings.h"
#include "nrf_dfu_req_handler.h"
#include "nrf_dfu_utils.h"
#include "nrf_dfu_validation.h"
#include "nordic_common.h"
#include "addr_parse.h"
#include "iot_errors.h"
#include "background_dfu_block.h"
#include "coap_block.h"

#include "thread_utils.h"

#include <openthread/coap.h>
#include <openthread/coap_secure.h>
#include <openthread/crypto.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/message.h>
#include <openthread/random_noncrypto.h>

#define NRF_LOG_LEVEL 4
#define NRF_LOG_MODULE_NAME COAP_DFU
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

// Remote firmware manifest server address.
static const uint8_t suit_remote_addr[16] =
        { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

static const uint16_t suit_remote_port = 5683;

// Maximum delay (in ms) between requesting consecutive image blocks.
#define DEFAULT_DELAY_MAX_MS    128

// Maximum number of events in the scheduler queue
#define SCHED_QUEUE_SIZE 	32

// Maximum app_scheduler event size
#define SCHED_EVENT_DATA_SIZE MAX(sizeof(nrf_dfu_request_t), APP_TIMER_SCHED_EVENT_DATA_SIZE)

// CoAP temporary buffer size
#define BUFFER_LENGTH            512

typedef struct
{
    uint8_t                  buffer[BUFFER_LENGTH]; // Last received CoAP payload.
    uint32_t                 buffer_length;         // Length of the last received CoAP payload.
    const char             * resource_path;         // Downloaded resource path on the remote host.
    uint8_t                  remote_addr[16];       // Remote address from which the resource is being downloaded.
    uint16_t                 remote_port;           // Remote port from which the resource is being downloaded.
    otCoapResponseHandler    handler;               // A pointer to the current response handler.
    bool                     timer_active;          // True if a CoAP request is pending, false otherwise.
} coap_dfu_context_t;

// CoAP token
static uint16_t m_coap_token;

// DFU client context
static background_dfu_context_t m_dfu_ctx;
static coap_dfu_context_t       m_coap_dfu_ctx;

// Timers
APP_TIMER_DEF(m_send_timer);
APP_TIMER_DEF(m_reset_timer);
APP_TIMER_DEF(m_coap_delayed_error_handling_timer);

// Remote SUIT resource URNs
static char * manifest_resource_name = "manifest.cbor";
static char image_resource_name[256];

static void reset_application(void)
{
    NRF_LOG_FINAL_FLUSH();

#if NRF_MODULE_ENABLED(NRF_LOG_BACKEND_RTT)
    // To allow the buffer to be flushed by the host.
    nrf_delay_ms(100);
#endif

    NVIC_SystemReset();
}

/**
 * @brief Function notifies certain events in DFU process.
 */
static void dfu_observer(nrf_dfu_evt_type_t evt_type)
{
    switch (evt_type)
    {
        case NRF_DFU_EVT_DFU_COMPLETED:
            // TODO: Terminate DTLS session.
            if (!m_dfu_ctx.reset_suppress)
            {
                NRF_LOG_INFO("Reset after DFU");
                reset_application();
            }
            else
            {
                NRF_LOG_INFO("Automatic reset suppressed by the server");
            }
            break;

        default:
            break;
    }
}

/***************************************************************************************************
 * @section Block processing
 **************************************************************************************************/

/** @brief Parse and return CoAP block option from a given message.
 *
 *  @param[in]  aMessage         A pointer to CoAP message.
 *  @param[out] p_block2_option  A pointer to parsed block 2 option.
 *
 *  @return True if message has Block2 option, false otherwise.
 */
static bool get_block2_opt(const otMessage          * aMessage, 
                           coap_block_opt_block2_t  * p_block2_option)
{
    otError error = OT_ERROR_NONE;
    otCoapOptionIterator aIterator;

    error = otCoapOptionIteratorInit(&aIterator, aMessage);
    if (error == OT_ERROR_PARSE)
    {
        NRF_LOG_ERROR("Failed to initialize option iterator.");
        return false;
    }

    const otCoapOption * aOption;
    aOption = otCoapOptionIteratorGetNextOptionMatching(&aIterator, OT_COAP_OPTION_BLOCK2);

    if (aOption == NULL)
    {
        NRF_LOG_ERROR("block2 option not found.");
        return false;
    }

    uint64_t aValue;
    error = otCoapOptionIteratorGetOptionUintValue(&aIterator, &aValue);
    if (error != OT_ERROR_NONE)
    {
        NRF_LOG_ERROR("Failed to copy block2 option from message.");
        return false;
    }

    if (coap_block_opt_block2_decode(p_block2_option, (uint32_t)aValue))
    {
        NRF_LOG_ERROR("Failed to decode block2 option.");
        return false;
    }

    return true;
}

/** @brief Set CoAP block2 option on a given message.
 *
 *  @param[inout]  aMessage     A pointer to CoAP message.
 *  @param[in]     block_size   Block size to set.
 *  @param[in]     block_number Block number to set.
 *
 *  @return NRF_SUCCESS if succesful, error code otherwise.
 */
static uint32_t set_block2_opt(otMessage      * aMessage,
                               uint16_t         block_size,
                               uint32_t         block_number)
{
    otError error = OT_ERROR_NONE;
    otCoapBlockSize aSize;

    switch(block_size)
    {
        case 16:
            aSize = OT_COAP_BLOCK_SIZE_16;
            break;
        case 32:
            aSize = OT_COAP_BLOCK_SIZE_32;
            break;
        case 64:
            aSize = OT_COAP_BLOCK_SIZE_64;
            break;
        case 128:
            aSize = OT_COAP_BLOCK_SIZE_128;
            break;
        case 256:
            aSize = OT_COAP_BLOCK_SIZE_256;
            break;
        case 512:
            aSize = OT_COAP_BLOCK_SIZE_512;
            break;
        case 1024:
            aSize = OT_COAP_BLOCK_SIZE_1024;
            break;
        default:
            NRF_LOG_ERROR("Invalid block size.");
            return NRF_ERROR_DATA_SIZE;
    }

    error = otCoapMessageAppendBlock2Option(aMessage, block_number, false, aSize);

    if (error)
    {
        NRF_LOG_ERROR("Failed to set block2 option.");
        return NRF_ERROR_DATA_SIZE;
    }
    
    return NRF_SUCCESS;
}

/***************************************************************************************************
 * @section Response handling
 **************************************************************************************************/

/**@brief Check status and common CoAP parameters for a response.
 *
 * @param[in] aResult    Response status code.
 * @param[in] aMessage   A response recevied. May be invalid if status is not NRF_SUCCESS.
 *
 * @return True if a valid response was received, false otherwise.
 */
static bool is_valid_response_received(otError aResult, const otMessage * aMessage)
{
    if (aResult != OT_ERROR_NONE)
    {
        if (aResult == OT_ERROR_RESPONSE_TIMEOUT)
        {
            NRF_LOG_WARNING("Request timeout");
        }
        else
        {
            NRF_LOG_WARNING("Unknown error");
        }

        return false;
    }

    if (otCoapMessageGetCode(aMessage) != OT_COAP_CODE_CONTENT)
    {
        NRF_LOG_WARNING("Request response code: %d", otCoapMessageGetCode(aMessage));

        return false;
    }

    if ((otCoapMessageGetTokenLength(aMessage) != sizeof(m_coap_token)) ||
        (memcmp(otCoapMessageGetToken(aMessage), &m_coap_token,
                otCoapMessageGetTokenLength(aMessage)) != 0))
    {
        NRF_LOG_WARNING("Token mismatch.");

        return false;
    }

    return true;
}

/**@brief CoAP response handler for metadata request sent to a SUIT manifest resource.
 *
 * An implementation of the otCoapRequestHandler function type.
 */
static void handle_manifest_metadata_response(void *aContext,
                                              otMessage *aMessage,
                                              const otMessageInfo *aMessageInfo,
                                              otError aResult)

{
    background_dfu_context_t * p_dfu_ctx = (background_dfu_context_t *)aContext;

    if (p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_MANIFEST_METADATA)
    {
        NRF_LOG_WARNING("Token response callback called in invalid state (s:%s)",
                (uint32_t)background_dfu_state_to_string(p_dfu_ctx->dfu_state));
        return;
    }

    if (!is_valid_response_received(aResult, aMessage))
    {
        background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_ERROR);
        return;
    }

    m_coap_dfu_ctx.buffer_length = otMessageRead(aMessage,
                                                 otMessageGetOffset(aMessage),
                                                 m_coap_dfu_ctx.buffer,
                                                 otMessageGetLength(aMessage));

    if (background_dfu_validate_manifest_metadata(&m_dfu_ctx,
                            m_coap_dfu_ctx.buffer, m_coap_dfu_ctx.buffer_length))
    {
        NRF_LOG_INFO("Manifest metadata received.");
	background_dfu_process_manifest_metadata(&m_dfu_ctx,
                            m_coap_dfu_ctx.buffer, m_coap_dfu_ctx.buffer_length);
    }
}

/**@brief CoAP response handler for requests sent with a block2 option.
 *
 * An implementation of the otCoapRequestHandler function type.
 */
static void handle_block_response(void *aContext,
                                  otMessage *aMessage,
                                  const otMessageInfo *aMessageInfo,
                                  otError aResult)
{
    coap_block_opt_block2_t    block_opt = {0};
    background_dfu_context_t * p_dfu_ctx = (background_dfu_context_t *)aContext;

    do
    {
        if ((p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE) &&
            (p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE))
        {
            NRF_LOG_WARNING("Block response callback called in invalid state (s:%s)",
                    (uint32_t)background_dfu_state_to_string(p_dfu_ctx->dfu_state));
            return;
        }

        if (!is_valid_response_received(aResult, aMessage))
        {
            background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_ERROR);
            break;
        }

        if (!get_block2_opt(aMessage, &block_opt))
        {
            NRF_LOG_WARNING("No block 2 option in response message.");
            background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_CONTINUE);
            break;
        }

        NRF_LOG_DEBUG("Received block %3lu", block_opt.number);

        if (block_opt.number != p_dfu_ctx->block_num)
        {
            NRF_LOG_WARNING("Requested %d but got %d", p_dfu_ctx->block_num, block_opt.number);
            background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_CONTINUE);
            break;
        }

        m_coap_dfu_ctx.buffer_length = otMessageRead(aMessage,
                                       otMessageGetOffset(aMessage),
                                       m_coap_dfu_ctx.buffer,
                                       otMessageGetLength(aMessage));

        background_dfu_block_t block;
        block.number    = block_opt.number;
        block.size      = block_opt.size;
	block.p_payload = m_coap_dfu_ctx.buffer;

        background_dfu_process_block(p_dfu_ctx, &block);

    } while (0);
}

/***************************************************************************************************
 * @section Message helpers
 **************************************************************************************************/

/** @brief Extract and parse a URI from the current SUIT manifest.
 *
 *  @return NRF_SUCCESS if succesful, error code otherwise.
 */
static uint32_t parse_manifest_uri(background_dfu_context_t * p_dfu_ctx, char * resource_name)
{
    char uri[256];
    uint32_t err;

    if ((err = nrf_dfu_validation_get_component_uri(0, uri)))
    {
        return err;
    }

    char * urn;
    size_t urn_len;
    bool use_dtls;

    if ((err = addr_parse_uri((uint8_t *)&m_coap_dfu_ctx.remote_addr,
                              &m_coap_dfu_ctx.remote_port,
                              &urn, &urn_len, &use_dtls,
                              uri, (uint8_t)(strlen(uri)))))
    {
        if (use_dtls)
        {
            NRF_LOG_INFO("Remote resource requires CoAPs.");
        }
        return err;
    }
    else
    {
        // Copy resource name into NULL-terminated string.
        resource_name[urn_len] = 0;
        memcpy(resource_name, urn, urn_len);

        NRF_LOG_INFO("Remote firmware resource at URN: %s", resource_name);
        NRF_LOG_HEXDUMP_INFO(&m_coap_dfu_ctx.remote_addr, 16);
    }

    return NRF_SUCCESS;
}

/**@brief Create a CoAP message with specific payload and remote.
 *
 * @param[in]  p_resource  A pointer to a string with resource name.
 * @param[in]  p_query     A pointer to a string with query string or NULL.
 * @param[in]  p_payload   A pointer to the message payload. NULL if message shall not contain any payload.
 * @param[in]  payload_len Payload length in bytes, ignored if p_payload is NULL.
 * @param[in]  aCode       CoAP message code.
 * @param[in]  aType       CoAP message type.
 * @param[in]  new_token   Generate new token if true.
 *
 * @return A pointer to the message created or NULL if could not be created.
 */
static otMessage * message_create(const char                * p_resource,
                                  const char                * p_query,
                                  const uint8_t             * p_payload,
                                  uint16_t                    payload_len,
				  otCoapCode                  aCode,
				  otCoapType                  aType,
				  bool                        new_token)
{
    uint32_t        err_code = NRF_SUCCESS;
    otMessage     * aMessage = otCoapNewMessage(thread_ot_instance_get(), NULL);

    otCoapMessageInit(aMessage, aType, aCode);

    if (new_token)
    {
    	otCoapMessageGenerateToken(aMessage, 2);
    	memcpy(&m_coap_token, otCoapMessageGetToken(aMessage), 2);
    }

    do
    {
        if (p_resource != NULL)
        {
            if (otCoapMessageAppendUriPathOptions(aMessage, p_resource) != OT_ERROR_NONE)
            {
                NRF_LOG_ERROR("Failed to append URI path options.");
                err_code = NRF_ERROR_INTERNAL;
                break;
            }
        }

        if (p_payload != NULL)
        {
            if (otMessageAppend(aMessage, p_payload, payload_len) != OT_ERROR_NONE)
            {
                NRF_LOG_ERROR("Failed to append message payload.");
                err_code = NRF_ERROR_INTERNAL;
                break;
            }
        }

        if (p_query != NULL)
        {
            NRF_LOG_INFO("Appending URI query: %s", p_query);
            if (otCoapMessageAppendUriQueryOption(aMessage, p_query) != OT_ERROR_NONE)
            {
                NRF_LOG_ERROR("Failed to append URI query options.");
                err_code = NRF_ERROR_INTERNAL;
                break;
            }
        }

    } while (0);

    if ((err_code != NRF_SUCCESS))
    {
        otMessageFree(aMessage);
    }

    return aMessage;
}

/**@brief A function for sending CoAP messages.
 *
 * @param[inout] p_request A pointer to CoAP message which should be sent.
 */
static void coap_dfu_message_send(otMessage * aMessage)
{
    //NRF_LOG_DEBUG("Sending message [mid:%d]", otCoapGetMessageId(aMessage));

    otMessageInfo aMessageInfo;
    memset(&aMessageInfo, 0, sizeof(aMessageInfo));
    memcpy(aMessageInfo.mPeerAddr.mFields.m8, m_coap_dfu_ctx.remote_addr, 16);
    aMessageInfo.mPeerPort = m_coap_dfu_ctx.remote_port;

    otError error = otCoapSendRequest(thread_ot_instance_get(),
                                      aMessage,
                                      &aMessageInfo,
                                      m_coap_dfu_ctx.handler,
                                      &m_dfu_ctx);

    if (error != OT_ERROR_NONE)
    {
        if (aMessage != NULL)
        {
            otMessageFree(aMessage);
        }

        // Notify application about internal error.
        if (m_coap_dfu_ctx.handler)
        {
            app_timer_start(m_coap_delayed_error_handling_timer, APP_TIMER_TICKS(1000*COAP_MAX_TRANSMISSION_SPAN), NULL);
        }

        NRF_LOG_ERROR("Failed to send CoAP message");
    }
}

/***************************************************************************************************
 * @section Timer handlers
 **************************************************************************************************/

static void delayed_send_handler(void * p_context)
{
    coap_dfu_message_send((otMessage *)p_context);

    m_coap_dfu_ctx.timer_active = false;
}

static void delayed_reset_handler(void * p_context)
{
    NRF_LOG_INFO("Handling delayed reset");

    reset_application();
}

/**@brief Handle events from m_coap_delayed_error_handling_timer.
 */
static void coap_delayed_error_handler(void * p_context)
{
    UNUSED_VARIABLE(p_context);

    NRF_LOG_INFO("Handling delayed dfu error handling");

    background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_ERROR);
}

/***************************************************************************************************
 * @section Private API
 **************************************************************************************************/

/**@brief Create COAP GET request.
 *
 * @param[in] resource_path   The URI of the resource which should be requested.
 * @param[in] p_query         A pointer to a string with query string or NULL.
 * @param[in] block_size      Requested block size.
 * @param[in] block_num       Requested block number.
 *
 * @return A pointer to CoAP message or NULL on error.
 */
static otMessage * coap_dfu_create_request(const char * resource_path,
                                           const char * p_query,
                                           uint16_t     block_size,
                                           uint32_t     block_num)
{
    uint32_t              err_code = NRF_SUCCESS;
    otMessage           * aMessage;

    do
    {
        aMessage = message_create(resource_path, p_query, NULL, 0,
			OT_COAP_CODE_GET, OT_COAP_TYPE_CONFIRMABLE, true);

        //p_request->p_arg = (void *)&m_dfu_ctx;

        if (block_size > 0)
        {
            err_code = set_block2_opt(aMessage, block_size, block_num);
            if (err_code != NRF_SUCCESS)
            {
                break;
            }
        }
    } while (0);

    if ((err_code != NRF_SUCCESS) && (aMessage != NULL))
    {
        otMessageFree(aMessage);
    }

    return aMessage;
}

static void coap_default_handler(void                * p_context,
                                 otMessage           * p_message,
                                 const otMessageInfo * p_message_info)
{
    (void)p_context;
    (void)p_message;
    (void)p_message_info;

    NRF_LOG_INFO("Received CoAP message that does not match any request or resource\r\n");
}

/**@brief Count blocks present in a block bitmap.
 *
 * @param[in] p_req_bmp A block bitmap to count.
 *
 * @return Number of blocks counted.
 */
static uint16_t blocks_count(const background_dfu_request_bitmap_t * p_req_bmp)
{
    uint16_t count = 0;

    for (uint8_t i = 0; i < p_req_bmp->size; i++)
    {
        for (uint8_t j = 0; j < 8; j++)
        {
            if ((p_req_bmp->bitmap[i] >> j) & 0x01)
            {
                count++;
            }
        }
    }

    return count;
}

/**@brief Initialize CoAP protocol.
 *
 * @return NRF_SUCCESS on success, otherwise an error code is returned.
 */
static uint32_t thread_coap_init()
{
    otError error = otCoapStart(thread_ot_instance_get(), OT_DEFAULT_COAP_PORT);
    ASSERT(error == OT_ERROR_NONE);

    otCoapSetDefaultHandler(thread_ot_instance_get(), coap_default_handler, NULL);

    return NRF_SUCCESS;
}

void background_dfu_transport_block_request_send(background_dfu_context_t        * p_dfu_ctx,
                                                 background_dfu_request_bitmap_t * p_req_bmp)
{
    uint16_big_encode(p_req_bmp->offset, (uint8_t *)&p_req_bmp->offset);

    NRF_LOG_INFO("Sending block request!");

    const char * p_resource_name  = NULL;

    if (m_dfu_ctx.dfu_state == BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE)
    {
        m_dfu_ctx.dfu_diag.manifest_blocks_requested += blocks_count(p_req_bmp);
        p_resource_name = manifest_resource_name;
    }
    else if (m_dfu_ctx.dfu_state == BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE)
    {
        m_dfu_ctx.dfu_diag.image_blocks_requested += blocks_count(p_req_bmp);
        p_resource_name = (char *)image_resource_name;
    }

    otMessage * aMessage =  message_create(p_resource_name, NULL,
                                           (uint8_t *)(&p_req_bmp->offset),
                                           sizeof(p_req_bmp->bitmap) + sizeof(uint16_t),
                                           OT_COAP_CODE_PUT,
                                           OT_COAP_TYPE_NON_CONFIRMABLE,
                                           false);

    coap_dfu_message_send(aMessage);
}

uint32_t background_dfu_random(void)
{
    return otRandomNonCryptoGetUint32();
}

void background_dfu_transport_state_update(background_dfu_context_t * p_dfu_ctx)
{
    switch (p_dfu_ctx->dfu_state)
    {
        case BACKGROUND_DFU_GET_MANIFEST_METADATA:
            m_coap_dfu_ctx.resource_path = manifest_resource_name;
            m_coap_dfu_ctx.handler       = (otCoapResponseHandler)handle_manifest_metadata_response;
            break;

        case BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE:
            m_coap_dfu_ctx.resource_path = manifest_resource_name;
            m_coap_dfu_ctx.handler       = (otCoapResponseHandler)handle_block_response;
            break;

        case BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE:

            // Get the remote URI and resource name from the stored manifest.
            parse_manifest_uri(p_dfu_ctx, image_resource_name);

            m_coap_dfu_ctx.resource_path = image_resource_name;
            m_coap_dfu_ctx.handler       = (otCoapResponseHandler)handle_block_response;
            break;

        case BACKGROUND_DFU_WAIT_FOR_RESET:
        case BACKGROUND_DFU_IDLE:
            break;

        default:
            NRF_LOG_WARNING("Unhandled state in background_dfu_transport_state_update (s: %s).",
                    (uint32_t)background_dfu_state_to_string(p_dfu_ctx->dfu_state));
    }
}

void background_dfu_transport_send_request(background_dfu_context_t * p_dfu_ctx)
{
    // Manifest metadata requests are sent with a URI query "meta" and no block2 option. All others
    // use block2 without a query.

    uint16_t block_size = (p_dfu_ctx->dfu_state == BACKGROUND_DFU_GET_MANIFEST_METADATA) ?
                            0 : DEFAULT_BLOCK_SIZE;

    char * query = (p_dfu_ctx->dfu_state == BACKGROUND_DFU_GET_MANIFEST_METADATA) ?
                            "meta" : NULL;

    otMessage * aMessage = coap_dfu_create_request(m_coap_dfu_ctx.resource_path,
                                                   query,
                                                   block_size,
                                                   p_dfu_ctx->block_num);

    NRF_LOG_INFO("Requesting [%s] (block:%u)",
                    (uint32_t)m_coap_dfu_ctx.resource_path,
                    p_dfu_ctx->block_num);
                    //otCoapMessageGetMessageId(aMessage));

    coap_dfu_message_send(aMessage);
}

/***************************************************************************************************
 * @section Public API
 **************************************************************************************************/

void background_dfu_handle_error(void)
{
    coap_dfu_handle_error();
}

__WEAK void coap_dfu_handle_error(void)
{
    // Intentionally empty.
}

void coap_dfu_diagnostic_get(struct background_dfu_diagnostic *p_diag)
{
    if (p_diag)
    {
        memcpy(p_diag, &m_dfu_ctx.dfu_diag, sizeof(background_dfu_diagnostic_t));
        p_diag->state = m_dfu_ctx.dfu_state;
    }
}

uint32_t coap_dfu_trigger()
{
    NRF_LOG_INFO("Starting DFU.");

    if (m_dfu_ctx.dfu_state != BACKGROUND_DFU_IDLE)
    {
        NRF_LOG_WARNING("Invalid state");
        return NRF_ERROR_INVALID_STATE;
    }

    // Transition from DFU_IDLE to DFU_DOWNLOAD_TRIG.
    return background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE);
}

uint32_t coap_dfu_init(const void * p_context)
{
    uint32_t err_code;

    do
    {
        memset(&m_coap_dfu_ctx, 0, sizeof(m_coap_dfu_ctx));

        memcpy(&m_coap_dfu_ctx.remote_addr, suit_remote_addr, 16);
        m_coap_dfu_ctx.remote_port = suit_remote_port;

        err_code = thread_coap_init();
        if (err_code != NRF_SUCCESS)
        {
            break;
        }

        nrf_dfu_settings_init(false);
        nrf_dfu_req_handler_init(dfu_observer);

        background_dfu_state_init(&m_dfu_ctx);
        
        app_timer_create(&m_send_timer, APP_TIMER_MODE_SINGLE_SHOT, delayed_send_handler);
        app_timer_create(&m_reset_timer, APP_TIMER_MODE_SINGLE_SHOT, delayed_reset_handler);
        app_timer_create(&m_coap_delayed_error_handling_timer, APP_TIMER_MODE_SINGLE_SHOT, coap_delayed_error_handler);

        APP_SCHED_INIT(SCHED_EVENT_DATA_SIZE, SCHED_QUEUE_SIZE);

    } while (0);

    return err_code;
}

void coap_dfu_process(void)
{
    app_sched_execute();
}

void coap_dfu_reset_state(void)
{
    background_dfu_reset_state(&m_dfu_ctx);
}

/** @} */
