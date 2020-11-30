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

#include "background_dfu_transport.h"
#include "coaps_dfu.h"

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
#include "lidar_wrapper.h"

#include <openthread/coap.h>
#include <openthread/coap_secure.h>
#include <openthread/crypto.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/message.h>
#include <openthread/random_noncrypto.h>

#define NRF_LOG_LEVEL 4
#define NRF_LOG_MODULE_NAME coaps_dfu
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

// Remote firmware manifest server paramters.
static const uint8_t suit_remote_addr[16] =
        { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

#ifndef COAPS_DFU_DTLS_ENABLE
#define COAPS_DFU_DTLS_ENABLE 1 
#endif

#if COAPS_DFU_DTLS_ENABLE
static void coaps_connect(const uint8_t addr[16], const uint16_t port);
static const char * suit_psk_secret = "secret";
static const char * suit_psk_id = "identity";
static const uint16_t suit_remote_port = OT_DEFAULT_COAP_SECURE_PORT;
#else
static const uint16_t suit_remote_port = OT_DEFAULT_COAP_PORT;
#endif

// Maximum number of events in the scheduler queue
#define SCHED_QUEUE_SIZE 	32

// Maximum app_scheduler event size
#define SCHED_EVENT_DATA_SIZE MAX(sizeof(nrf_dfu_request_t), APP_TIMER_SCHED_EVENT_DATA_SIZE)

// CoAP temporary buffer size
#define RX_BUFF_LEN             512
#define TX_BUFF_LEN 		512

typedef struct
{
    uint8_t                  buffer[RX_BUFF_LEN];   // Last received CoAP payload.
    uint32_t                 buffer_length;         // Length of the last received CoAP payload.
    uint8_t                  payload[TX_BUFF_LEN];  // Send buffer.
    uint32_t                 payload_length;
    const char             * resource_path;         // Downloaded resource path on the remote host.
    uint8_t                  remote_addr[16];       // Remote address from which the resource is being downloaded.
    uint16_t                 remote_port;           // Remote port from which the resource is being downloaded.
    otCoapResponseHandler    handler;               // A pointer to the current response handler.
} coaps_dfu_context_t;

// CoAP token
static uint16_t m_coap_token;

// DFU client context
static background_dfu_context_t m_dfu_ctx;
static coaps_dfu_context_t       m_coaps_dfu_ctx;

// Remote resource URNs
static char * manifest_resource_name = "manifest.cbor";
static char image_resource_name[256];
#ifdef ENABLE_SENSOR
static char * sensor_resource_name = "sensor";
#endif

static void reset_application(void)
{
    NRF_LOG_FINAL_FLUSH();

#if NRF_MODULE_ENABLED(NRF_LOG_BACKEND_RTT)
    // To allow the buffer to be flushed by the host.
    nrf_delay_ms(100);
#endif
#if COAPS_DFU_DTLS_ENABLE
    otCoapSecureStop(thread_ot_instance_get());
    otCoapSecureDisconnect(thread_ot_instance_get());
    nrf_delay_ms(1000);
#endif

    NVIC_SystemReset();
}

// Function notifies certain events in DFU process.
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
 * @section Sensor handler
 **************************************************************************************************/

#ifdef ENABLE_SENSOR
int16_t read_sensor_data(uint8_t *buffer, uint16_t buf_len)
{
    uint32_t mean, hits;
    
    int ret = lidar_get_data(&mean, &hits);
    NRF_LOG_INFO("%d hits, %d mean %d ret", hits, mean, ret);
    
    nanocbor_encoder_t encoder;
    nanocbor_encoder_init(&encoder, buffer, buf_len);
    nanocbor_fmt_array(&encoder, 2);
    nanocbor_fmt_uint(&encoder, mean);
    nanocbor_fmt_uint(&encoder, hits);
    return nanocbor_encoded_len(&encoder);
}
#endif

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
 *  @param[i/o]  aMessage     A pointer to CoAP message.
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

// CoAP response handler for metadata request sent to a SUIT manifest resource.
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

    m_coaps_dfu_ctx.buffer_length = otMessageRead(aMessage,
                                                 otMessageGetOffset(aMessage),
                                                 m_coaps_dfu_ctx.buffer,
                                                 otMessageGetLength(aMessage));

    if (background_dfu_validate_manifest_metadata(&m_dfu_ctx,
                            m_coaps_dfu_ctx.buffer, m_coaps_dfu_ctx.buffer_length))
    {
        NRF_LOG_INFO("Manifest metadata received.");
	background_dfu_process_manifest_metadata(&m_dfu_ctx,
                            m_coaps_dfu_ctx.buffer, m_coaps_dfu_ctx.buffer_length);
    }
}

// CoAP response handler for requests sent with a block2 option.
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

        m_coaps_dfu_ctx.buffer_length = otMessageRead(aMessage,
                                       otMessageGetOffset(aMessage),
                                       m_coaps_dfu_ctx.buffer,
                                       otMessageGetLength(aMessage));

        background_dfu_block_t block;
        block.number    = block_opt.number;
        block.size      = block_opt.size;
	block.p_payload = m_coaps_dfu_ctx.buffer;

        background_dfu_process_block(p_dfu_ctx, &block);

    } while (0);
}

#ifdef ENABLE_SENSOR
static void handle_sensor_ack(void *aContext,
                              otMessage *aMessage,
                              const otMessageInfo *aMessageInfo,
                              otError aResult)

{
    if (otCoapMessageGetCode(aMessage) == OT_COAP_CODE_VALID) {
        return;
    } 
}
#endif

/***************************************************************************************************
 * @section Message helpers
 **************************************************************************************************/

/** @brief Extract and parse a URI from the current SUIT manifest.
 *
 * @param[in] p_dfu_ctx      A pointer to the current DFU context.
 * @param[in] resource_name  A pointer to a buffer to store the resource name. The current CoAP DFU
 *                           context will store this pointer as the current resource to download.
 *
 *  @return NRF_SUCCESS if succesful, error code otherwise.
 */
static uint32_t parse_uri_string(background_dfu_context_t * p_dfu_ctx, char * resource_name)
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

    if ((err = addr_parse_uri((uint8_t *)&m_coaps_dfu_ctx.remote_addr,
                              &m_coaps_dfu_ctx.remote_port,
                              &urn, &urn_len, &use_dtls,
                              uri, (uint8_t)(strlen(uri)))))
    {
        if (!use_dtls)
        {
            NRF_LOG_ERROR("Remote firmware resource does not use DTLS!");
        }
        return err;
    }
    else
    {
        // Copy resource name into NULL-terminated string.
        resource_name[urn_len] = 0;
        memcpy(resource_name, urn, urn_len);

        NRF_LOG_INFO("Remote firmware resource at URN: %s, port: %d",
                        resource_name, m_coaps_dfu_ctx.remote_port);
        NRF_LOG_HEXDUMP_INFO(&m_coaps_dfu_ctx.remote_addr, 16);
    }

    return NRF_SUCCESS;
}

/**@brief Create a CoAP message with specific payload and remote.
 *
 * @param[in]  p_resource     A pointer to a string with resource name.
 * @param[in]  p_query        A pointer to a string with query string or NULL.
 * @param[in]  p_payload      A pointer to the message payload. NULL if message shall not contain any payload.
 * @param[in]  payload_len    Payload length in bytes, ignored if p_payload is NULL.
 * @param[in]  aCode          CoAP message code.
 * @param[in]  aType          CoAP message type.
 * @param[in]  aContentFormat CoAP content format.
 *
 * @return A pointer to the message created or NULL if could not be created.
 */
static otMessage * message_create(const char    * p_resource,
                                  const char    * p_query,
                                  const uint8_t * p_payload,
                                  uint16_t        payload_len,
				  otCoapCode      aCode,
				  otCoapType      aType,
				  otCoapOptionContentFormat aContentFormat)
{
    otError     error;   
    otMessage * aMessage = otCoapNewMessage(thread_ot_instance_get(), NULL);

    otCoapMessageInit(aMessage, aType, aCode);
    
    // Generate a new token and store to match the response.
    otCoapMessageGenerateToken(aMessage, 2);
    memcpy(&m_coap_token, otCoapMessageGetToken(aMessage), 2);

   if (p_resource != NULL)
   {
       error = otCoapMessageAppendUriPathOptions(aMessage, p_resource);
       ASSERT(error == OT_ERROR_NONE);
   }

   if (p_payload != NULL)
   {
      error = otCoapMessageAppendContentFormatOption(aMessage, aContentFormat);
      ASSERT(error == OT_ERROR_NONE);

      error = otCoapMessageSetPayloadMarker(aMessage);
      ASSERT(error == OT_ERROR_NONE);

       error = otMessageAppend(aMessage, p_payload, payload_len);
       ASSERT(error == OT_ERROR_NONE);
       NRF_LOG_INFO("attach pload: %lu", payload_len);
   } else {
     NRF_LOG_DEBUG("No req pload");
   }

   if (p_query != NULL)
   {
       error = otCoapMessageAppendUriQueryOption(aMessage, p_query);
       ASSERT(error == OT_ERROR_NONE);
   }

    return aMessage;
}

/**@brief A function for sending CoAP messages.
 *
 * @param[i/o] p_request A pointer to CoAP message which should be sent.
 */
static void coaps_dfu_message_send(otMessage * aMessage)
{
#if COAPS_DFU_DTLS_ENABLE
    if (!otCoapSecureIsConnected(thread_ot_instance_get()) ||
        !otCoapSecureIsConnectionActive(thread_ot_instance_get()))
    {
        NRF_LOG_ERROR("DTLS connection not established.");
    }

    otError error = otCoapSecureSendRequest(thread_ot_instance_get(),
                                            aMessage,
                                            m_coaps_dfu_ctx.handler,
                                            &m_dfu_ctx);
#else
    otMessageInfo aMessageInfo;
    memset(&aMessageInfo, 0, sizeof(aMessageInfo));
    memcpy(aMessageInfo.mPeerAddr.mFields.m8, m_coaps_dfu_ctx.remote_addr, 16);
    aMessageInfo.mPeerPort = m_coaps_dfu_ctx.remote_port;

    otError error = otCoapSendRequest(thread_ot_instance_get(),
                                      aMessage,
                                      &aMessageInfo,
                                      m_coaps_dfu_ctx.handler,
                                      &m_dfu_ctx);
#endif

    if (error != OT_ERROR_NONE)
    {
        // Notify application about internal error.
        if (m_coaps_dfu_ctx.handler)
        {
            background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_ERROR);
        }

        if (aMessage != NULL)
        {
            otMessageFree(aMessage);
        }

        NRF_LOG_ERROR("Failed to send CoAP message");
    }
}

/***************************************************************************************************
 * @section Private API
 **************************************************************************************************/

/**@brief Create a CoAP GET/POST request.
 *
 * @param[in] resource_path   The URI of the resource which should be requested.
 * @param[in] p_query         A pointer to a string with query string or NULL.
 * @param[in] req_payload     byte array pointer
 * @param[in] req_payload_len length of request payload
 * @param[in] block_size      Requested block size.
 * @param[in] block_num       Requested block number.
 * @param[in] aCode           GET or POST
 * @param[in] aContentFormat  CoAP content format.
 *
 * @return A pointer to CoAP message or NULL on error.
 */

static otMessage * coaps_dfu_create_request(const char * resource_path,
                                           const char * p_query,
                                           uint8_t * req_payload,
                                           uint16_t   payload_len,
                                           uint16_t     block_size,
                                           uint32_t     block_num,
                                           otCoapCode      aCode,
                                           otCoapOptionContentFormat aContentFormat
                                           )

{
    otMessage * aMessage;
    aMessage = message_create(resource_path, p_query, req_payload, payload_len,
        aCode, OT_COAP_TYPE_CONFIRMABLE, aContentFormat);

    if (block_size > 0)
    {
        if (set_block2_opt(aMessage, block_size, block_num) != NRF_SUCCESS)
        {
            otMessageFree(aMessage);
        }
    }

    return aMessage;
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

/***************************************************************************************************
 * @section Functions defined in other header files
 **************************************************************************************************/

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
                                           OT_COAP_TYPE_NON_CONFIRMABLE, 0);

    coaps_dfu_message_send(aMessage);
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
            m_coaps_dfu_ctx.resource_path = manifest_resource_name;
            m_coaps_dfu_ctx.handler       = (otCoapResponseHandler)handle_manifest_metadata_response;
            break;

        case BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE:
            m_coaps_dfu_ctx.resource_path = manifest_resource_name;
            m_coaps_dfu_ctx.handler       = (otCoapResponseHandler)handle_block_response;
            break;

        case BACKGROUND_DFU_WAIT_FOR_CONNECTION:
            // Get the remote URI and resource name from the stored manifest.
            parse_uri_string(p_dfu_ctx, image_resource_name);

#if COAPS_DFU_DTLS_ENABLE
            coaps_connect(m_coaps_dfu_ctx.remote_addr, m_coaps_dfu_ctx.remote_port);
#else
            // The firmware image download can begin immediately if DTLS is disabled.
            background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE);
#endif
            break;

        case BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE:
            m_coaps_dfu_ctx.resource_path = image_resource_name;
            m_coaps_dfu_ctx.handler       = (otCoapResponseHandler)handle_block_response;
            break;

        case BACKGROUND_DFU_WAIT_FOR_RESET:
        case BACKGROUND_DFU_IDLE:
            break;

        case TRANSMIT_SENSOR_DATA:
#ifdef ENABLE_SENSOR
  	    m_coaps_dfu_ctx.resource_path = sensor_resource_name;
   	    int len = read_sensor_data(m_coaps_dfu_ctx.payload, TX_BUFF_LEN);
    	    m_coaps_dfu_ctx.payload_length = len;
    	    m_coaps_dfu_ctx.handler = (otCoapResponseHandler)handle_sensor_ack;
#endif
            break;

        default:
            NRF_LOG_WARNING("Unhandled state in background_dfu_transport_state_update (s: %s).",
                    (uint32_t)background_dfu_state_to_string(p_dfu_ctx->dfu_state));
    }
}

void background_dfu_transport_send_request(background_dfu_context_t * p_dfu_ctx)
{
    uint16_t block_size;
    char * query;
    uint16_t payload_len = 0;
    uint8_t * payload = NULL;

    otCoapCode aCode = OT_COAP_CODE_GET;
    otCoapOptionContentFormat aContentFormat = 0;

    switch (p_dfu_ctx->dfu_state)
    {
        case BACKGROUND_DFU_GET_MANIFEST_METADATA:
            block_size = 0;
            query = "meta";
            break;

	case TRANSMIT_SENSOR_DATA:
	    block_size = 0;
	    payload = m_coaps_dfu_ctx.payload;
	    payload_len = m_coaps_dfu_ctx.payload_length;
	    query = NULL;
	    aCode = OT_COAP_CODE_PUT;

        default:
            block_size = DEFAULT_BLOCK_SIZE;
            query = NULL;
    }

    otMessage * aMessage = coaps_dfu_create_request(
		    m_coaps_dfu_ctx.resource_path,
                    query,
                    payload,
                    payload_len,
                    block_size,
                    p_dfu_ctx->block_num,
                    aCode,
                    aContentFormat
    );

    NRF_LOG_INFO("Requesting [%s] (block:%u)",
                    (uint32_t)m_coaps_dfu_ctx.resource_path,
                    p_dfu_ctx->block_num);

    coaps_dfu_message_send(aMessage);
}

void background_dfu_handle_error(void)
{
    coaps_dfu_handle_error();
}

/***************************************************************************************************
 * @section CoAP(s) initialization
 **************************************************************************************************/

static void coap_default_handler(void                * p_context,
                                 otMessage           * p_message,
                                 const otMessageInfo * p_message_info)
{
    (void)p_context;
    (void)p_message;
    (void)p_message_info;

    NRF_LOG_INFO("Received CoAP message that does not match any request or resource\r\n");
}

#if COAPS_DFU_DTLS_ENABLE
static void coaps_connect_handler(bool connected, void *aContext)
{
    if (connected)
    {
        NRF_LOG_INFO("CoAPs session established.");
        background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE);
    }
    else
    {
        NRF_LOG_ERROR("Failed to establish CoAPs session.");
    }
}

static void coaps_connect(const uint8_t addr[16], const uint16_t port)
{
    if (otCoapSecureIsConnected(thread_ot_instance_get()))
    {
        NRF_LOG_INFO("Terminating existing DTLS session.");

	otCoapSecureDisconnect(thread_ot_instance_get());

        // FIXME: This works, but it seems like overkill. The disconnect command doesn't appear to
        // work without restarting the entire CoAPs backend.
        otCoapSecureStop(thread_ot_instance_get());
        otError error = otCoapSecureStart(thread_ot_instance_get(), OT_DEFAULT_COAP_SECURE_PORT);
        ASSERT(error == OT_ERROR_NONE);

        otCoapSecureSetDefaultHandler(thread_ot_instance_get(), coap_default_handler, NULL);
    }

    otSockAddr aSockAddr;
    memset(&aSockAddr, 0, sizeof(aSockAddr));

    aSockAddr.mPort = port;
    memcpy(&aSockAddr.mAddress.mFields.m8, addr, 16);

    otCoapSecureSetPsk(thread_ot_instance_get(),
                       (const uint8_t *)suit_psk_secret, strlen(suit_psk_secret),
                       (const uint8_t *)suit_psk_id, strlen(suit_psk_id));

    otError error = otCoapSecureConnect(thread_ot_instance_get(),
                                        &aSockAddr,
                                        coaps_connect_handler,
                                        &m_dfu_ctx);

    ASSERT(error == OT_ERROR_NONE);
}
#endif

static uint32_t thread_coap_init()
{
    otError error;

#if COAPS_DFU_DTLS_ENABLE
    error = otCoapSecureStart(thread_ot_instance_get(), OT_DEFAULT_COAP_SECURE_PORT);
    ASSERT(error == OT_ERROR_NONE);

    otCoapSecureSetDefaultHandler(thread_ot_instance_get(), coap_default_handler, NULL);
    coaps_connect(suit_remote_addr, suit_remote_port);
#else
    error = otCoapStart(thread_ot_instance_get(), OT_DEFAULT_COAP_PORT);
    ASSERT(error == OT_ERROR_NONE);

    otCoapSetDefaultHandler(thread_ot_instance_get(), coap_default_handler, NULL);
#endif

    return NRF_SUCCESS;
}

/***************************************************************************************************
 * @section Public API
 **************************************************************************************************/

__WEAK void coaps_dfu_handle_error(void)
{
    // Intentionally empty.
}

void coaps_dfu_diagnostic_get(struct background_dfu_diagnostic *p_diag)
{
    if (p_diag)
    {
        memcpy(p_diag, &m_dfu_ctx.dfu_diag, sizeof(background_dfu_diagnostic_t));
        p_diag->state = m_dfu_ctx.dfu_state;
    }
}

uint32_t coaps_dfu_start()
{
    NRF_LOG_INFO("Starting DFU.");

    if (m_dfu_ctx.dfu_state != BACKGROUND_DFU_IDLE)
    {
        NRF_LOG_WARNING("Invalid state");
        return NRF_ERROR_INVALID_STATE;
    }

    uint32_t err_code = thread_coap_init();
    ASSERT(err_code == NRF_SUCCESS);

    /* If DTLS is not enabled, we can transition from DFU_IDLE to DFU_GET_MANIFEST_METADATA
     * immediately. Otherwise, this transition is triggered by the CoAPs connection callback upon
     * completion of the handshake with the remote server.
     *
     * If ENABLE_SENSOR is defined, the next state will be TRANSMIT_SENSOR_DATA instead.
     */

#if COAPS_DFU_DTLS_ENABLE
    return NRF_SUCCESS;
#else
    return background_dfu_handle_event(&m_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE);
#endif
}

uint32_t coaps_dfu_init(const void * p_context)
{
    memset(&m_coaps_dfu_ctx, 0, sizeof(m_coaps_dfu_ctx));
    
    memcpy(&m_coaps_dfu_ctx.remote_addr, suit_remote_addr, 16);
    m_coaps_dfu_ctx.remote_port = suit_remote_port;
    
    nrf_dfu_settings_init(false);
    nrf_dfu_req_handler_init(dfu_observer);
    
    background_dfu_state_init(&m_dfu_ctx);
    
    APP_SCHED_INIT(SCHED_EVENT_DATA_SIZE, SCHED_QUEUE_SIZE);

    return NRF_SUCCESS;
}

void coaps_dfu_reset_state(void)
{
    background_dfu_reset_state(&m_dfu_ctx);
}
