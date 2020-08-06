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
 * @defgroup background_dfu_state background_dfu_state.c
 * @{
 * @ingroup background_dfu
 * @brief Background DFU state management.
 *
 */

#include "background_dfu_state.h"

#include <string.h>

#include "sdk_config.h"
#include "app_timer.h"
#include "compiler_abstraction.h"
#include "nrf_dfu_types.h"
#include "nrf_dfu_settings.h"
#include "nrf_dfu_validation.h"
#include "crc32.h"
#include "sha256.h"
#include "background_dfu_transport.h"
#include "background_dfu_operation.h"
#include "nanocbor/nanocbor.h"

#define NRF_LOG_MODULE_NAME background_dfu

#define NRF_LOG_LEVEL       BACKGROUND_DFU_CONFIG_LOG_LEVEL
#define NRF_LOG_INFO_COLOR  BACKGROUND_DFU_CONFIG_INFO_COLOR
#define NRF_LOG_DEBUG_COLOR BACKGROUND_DFU_CONFIG_DEBUG_COLOR

#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#define BLOCK_REQUEST_JITTER_MIN    200     /**< Minimum jitter value when sending bitmap with requested blocks in multicast DFU. */
#define BLOCK_REQUEST_JITTER_MAX    2000    /**< Maximum jitter value when sending bitmap with requested blocks in multicast DFU. */
#define BLOCK_RECEIVE_TIMEOUT       2000    /**< Timeout value after which block is considered missing in multicast DFU. */

#define DFU_DATE_TIME               (__DATE__ " " __TIME__)

APP_TIMER_DEF(m_missing_block_timer);
APP_TIMER_DEF(m_block_timeout_timer);

/**@brief Defines how many retries are performed in case no response is received. */
#define DEFAULT_RETRIES         3

/**@brief DFU error handler.
 *
 * @param[inout] p_dfu_ctx DFU context.
 */
static __INLINE void dfu_handle_error(background_dfu_context_t * p_dfu_ctx)
{
    p_dfu_ctx->dfu_state = BACKGROUND_DFU_ERROR;

    background_dfu_handle_error();
}

/**@brief Get randomized jitter value.
 *
 * @return Randomized jitter value between BLOCK_REQUEST_JITTER_MIN and BLOCK_REQUEST_JITTER_MAX.
 */
static __INLINE uint32_t block_request_jitter_get(void)
{
    return BLOCK_REQUEST_JITTER_MIN + (background_dfu_random() %
            (BLOCK_REQUEST_JITTER_MAX - BLOCK_REQUEST_JITTER_MIN));
}

/**@brief Starts block timeout timer.
 *
 * @param[inout] p_dfu_ctx DFU context.
 */
static __INLINE void start_block_timeout_timer(background_dfu_context_t * p_dfu_ctx)
{
    uint32_t err_code = app_timer_start(m_block_timeout_timer,
                                        APP_TIMER_TICKS(BLOCK_RECEIVE_TIMEOUT),
                                        p_dfu_ctx);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in app_timer_start (%d)", err_code);
    }
}

/**@brief Stops block timeout timer.
 *
 * @param[inout] p_dfu_ctx DFU context.
 */
static __INLINE void stop_block_timeout_timer(background_dfu_context_t * p_dfu_ctx)
{
    UNUSED_PARAMETER(p_dfu_ctx);
    uint32_t err_code = app_timer_stop(m_block_timeout_timer);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in app_timer_stop (%d)", err_code);
    }
}

/**@brief Restarts block timeout timer.
 *
 * @param[inout] p_dfu_ctx DFU context.
 */
static __INLINE void restart_block_timeout_timer(background_dfu_context_t * p_dfu_ctx)
{
    stop_block_timeout_timer(p_dfu_ctx);
    start_block_timeout_timer(p_dfu_ctx);
}

/***************************************************************************************************
 * @section Handle SUIT Manifest (DFU Trigger)
 **************************************************************************************************/

// TODO: Check if this has security implications. This should probably be declared static so
// application code cannot modify it directly.

bool background_dfu_validate_manifest_metadata(background_dfu_context_t * p_dfu_ctx,
                                               const uint8_t            * p_payload,
                                               uint32_t                   payload_len)
{
    if ((p_dfu_ctx->dfu_state != BACKGROUND_DFU_IDLE) &&
        (p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_MANIFEST_METADATA))
    {
        NRF_LOG_ERROR("Validate manifest metadata: DFU already in progress (s:%s).",
                (uint32_t)background_dfu_state_to_string(p_dfu_ctx->dfu_state));
        return false;
    }

    nanocbor_value_t nc, arr;
    nanocbor_decoder_init(&nc, p_payload, payload_len);

    if (nanocbor_enter_array(&nc, &arr) < 0) goto metadata_fail;
    if (nanocbor_get_uint32(&arr, &p_dfu_ctx->suit_manifest_size) < 0) goto metadata_fail;
    if (nanocbor_get_uint32(&arr, &p_dfu_ctx->suit_manifest_crc) < 0) goto metadata_fail;

    NRF_LOG_INFO("size = %ld, crc32 = %ld", p_dfu_ctx->suit_manifest_size,
                                            p_dfu_ctx->suit_manifest_crc);
    return true;

metadata_fail:
    NRF_LOG_ERROR("Failed to decode SUIT manifest metadata.");
    return false;
}

/*
extern suit_context_t m_suit_ctx;

bool background_dfu_validate_manifest(background_dfu_context_t * p_dfu_ctx,
                                      const uint8_t            * p_payload,
                                      uint32_t                   payload_len)
{
    if ((p_dfu_ctx->dfu_state != BACKGROUND_DFU_IDLE) &&
        (p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_MANIFEST_METADATA))
    {
        NRF_LOG_ERROR("Validate manifest: DFU already in progress (s:%s).",
                (uint32_t)background_dfu_state_to_string(p_dfu_ctx->dfu_state));
        return false;
    }

    if (!nrf_dfu_manifest_decode(p_payload, payload_len))
    {
        NRF_LOG_ERROR("Failed to decode SUIT manifest.");
        return false;
    }
    else
    {
        p_dfu_ctx->suit_manifest_size = payload_len;
        p_dfu_ctx->suit_manifest_crc  = crc32_compute(p_payload, payload_len, NULL);
        p_dfu_ctx->firmware_size = m_suit_ctx.components[0].size;
        p_dfu_ctx->firmware_crc  = 0;
        p_dfu_ctx->dfu_mode = BACKGROUND_DFU_MODE_UNICAST;
    }

    return true;
}

bool background_dfu_process_manifest(background_dfu_context_t * p_dfu_ctx,
                                     const uint8_t            * p_payload,
                                     uint32_t                   payload_len)
{
    p_dfu_ctx->dfu_state = BACKGROUND_DFU_GET_MANIFEST_METADATA;

    uint32_t err;
    if ((err = background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE)))
    {
        NRF_LOG_ERROR("Error in background_dfu_handle_event (0x%d)", err);
    }

    NRF_LOG_INFO("SUIT DFU: manifest (sz=%d, crc=%0X) image (sz=%d, crc=%0X)",
            p_dfu_ctx->suit_manifest_size,
            p_dfu_ctx->suit_manifest_crc,
            p_dfu_ctx->firmware_size,
            p_dfu_ctx->firmware_crc);

    return true;
}
*/

/***************************************************************************************************
 * @section DFU checks
 **************************************************************************************************/

background_dfu_block_result_t background_dfu_process_block(background_dfu_context_t     * p_dfu_ctx,
                                                           const background_dfu_block_t * p_block)
{
    background_dfu_block_result_t result = block_manager_block_process(&p_dfu_ctx->block_manager,
                                                                       p_block);
    uint32_t err_code = NRF_SUCCESS;

    switch (result)
    {
        case  BACKGROUND_DFU_BLOCK_IGNORE:
            // Ignore.
            if (p_dfu_ctx->dfu_mode == BACKGROUND_DFU_MODE_MULTICAST)
            {
                restart_block_timeout_timer(p_dfu_ctx);
            }

            break;

        case BACKGROUND_DFU_BLOCK_SUCCESS:
            // Intentionally empty.
            break;

        default:
            err_code = background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_PROCESSING_ERROR);
            if (err_code != NRF_SUCCESS)
            {
                NRF_LOG_ERROR("Error in background_dfu_handle_event (%d)", err_code);
            }

            break;
    }

    return result;
}

/**@brief Check if installed image is different from the incoming one.
 *
 * @param[in] p_dfu_ctx A pointer to DFU client context.
 *
 * @return True if image different, false otherwise.
 *
 */
static bool is_image_different(const background_dfu_context_t * p_dfu_ctx)
{
    if (s_dfu_settings.bank_0.bank_code == NRF_DFU_BANK_INVALID)
    {
        NRF_LOG_WARNING("No image in bank 0");
        return true;
    }

    if (s_dfu_settings.bank_0.image_crc != p_dfu_ctx->firmware_crc)
    {
        NRF_LOG_WARNING("Installed image CRC is different");
        return true;
    }

    return false;
}

/**
 * @brief A callback function for block manager.
 */
static void dfu_block_manager_result_handler(background_dfu_block_result_t result, void * p_context)
{
    background_dfu_context_t * p_dfu_ctx = p_context;
    uint32_t                   err_code;

    if (result == BACKGROUND_DFU_BLOCK_SUCCESS)
    {
        if (p_dfu_ctx->dfu_mode == BACKGROUND_DFU_MODE_MULTICAST)
        {
            restart_block_timeout_timer(p_dfu_ctx);
        }

        if (block_manager_is_image_complete(&p_dfu_ctx->block_manager))
        {
            err_code = background_dfu_handle_event(p_dfu_ctx,
                                                   BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE);
            if (err_code != NRF_SUCCESS)
            {
                NRF_LOG_ERROR("Error in background_dfu_handle_event (%d)", err_code);
            }
        }
        else
        {
            // FIXME I don't like it here.
            p_dfu_ctx->block_num++;

            err_code = background_dfu_handle_event(p_dfu_ctx,
                                                   BACKGROUND_DFU_EVENT_TRANSFER_CONTINUE);
            if (err_code != NRF_SUCCESS)
            {
                NRF_LOG_ERROR("Error in background_dfu_handle_event (%d)", err_code);
            }
        }
    }
    else
    {
        err_code = background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_PROCESSING_ERROR);
        if (err_code != NRF_SUCCESS)
        {
            NRF_LOG_ERROR("Error in background_dfu_handle_event (%d)", err_code);
        }
    }
}

/**
 * @brief Prepare state machine to download init command.
 */
static void setup_download_init_command(background_dfu_context_t * p_dfu_ctx)
{
    p_dfu_ctx->p_resource_size = &p_dfu_ctx->suit_manifest_size;
    p_dfu_ctx->retry_count     = DEFAULT_RETRIES;
    p_dfu_ctx->block_num       = 0;

    background_dfu_transport_state_update(p_dfu_ctx);

    block_manager_init(&p_dfu_ctx->block_manager,
                       p_dfu_ctx->dfu_state,
                       *p_dfu_ctx->p_resource_size,
                       p_dfu_ctx->block_num,
                       dfu_block_manager_result_handler,
                       p_dfu_ctx);

    if (p_dfu_ctx->dfu_mode == BACKGROUND_DFU_MODE_MULTICAST)
    {
        NRF_LOG_INFO("Init complete. Multicast Mode.");
        uint32_t jitter = block_request_jitter_get();
        uint32_t err_code = app_timer_start(m_missing_block_timer,
                                            APP_TIMER_TICKS(jitter),
                                            p_dfu_ctx);
        if (err_code != NRF_SUCCESS)
        {
            NRF_LOG_ERROR("Error in app_timer_start (%d)", err_code);
        }
    }
    else
    {
        NRF_LOG_INFO("Init complete. Unicast Mode.");
    }
}

/**
 * @brief A callback function for DFU command operations.
 */
static void dfu_init_check_callback(nrf_dfu_response_t * p_res, void * p_context)
{
    background_dfu_context_t * p_dfu_ctx = (background_dfu_context_t *)p_context;

    switch (p_res->request)
    {
        case NRF_DFU_OP_OBJECT_SELECT:
            if (p_res->result != NRF_DFU_RES_CODE_SUCCESS)
            {
                NRF_LOG_ERROR("No valid init command - select failed");
                setup_download_init_command((background_dfu_context_t *)p_context);

                UNUSED_RETURN_VALUE(background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_CONTINUE));
            }

            p_dfu_ctx->max_obj_size = p_res->select.max_size;
            p_dfu_ctx->block_num    = p_res->select.offset / DEFAULT_BLOCK_SIZE;

            if (background_dfu_op_execute(dfu_init_check_callback, p_context) != NRF_SUCCESS)
            {
                NRF_LOG_ERROR("No valid init command - execute error");
                setup_download_init_command((background_dfu_context_t *)p_context);

                UNUSED_RETURN_VALUE(background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_CONTINUE));
            }

            break;

        case NRF_DFU_OP_OBJECT_EXECUTE:
            if ((p_res->result != NRF_DFU_RES_CODE_SUCCESS) ||
                (s_dfu_settings.progress.manifest_crc != p_dfu_ctx->suit_manifest_crc))
            {
                NRF_LOG_ERROR("Init commad has changed");
                p_dfu_ctx->remaining_size = 0;
                setup_download_init_command((background_dfu_context_t *)p_context);

                UNUSED_RETURN_VALUE(background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_CONTINUE));
            }
            else
            {
                // Valid init command stored, download firmware.
                p_dfu_ctx->dfu_diag.state = BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE;

                UNUSED_RETURN_VALUE(background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE));
            }

            break;

        default:
            ASSERT(false);
    }
}

/**
 * @brief A callback function for DFU data operation.
 */
static void dfu_data_select_callback(nrf_dfu_response_t * p_res, void * p_context)
{
    ASSERT(p_res->request == NRF_DFU_OP_OBJECT_SELECT);

    background_dfu_context_t * p_dfu_ctx = (background_dfu_context_t *)p_context;
    if (p_res->result != NRF_DFU_RES_CODE_SUCCESS)
    {
        NRF_LOG_ERROR("Select failed");
        dfu_handle_error(p_dfu_ctx);
        return;
    }

    p_dfu_ctx->dfu_state       = BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE;
    p_dfu_ctx->p_resource_size = &p_dfu_ctx->firmware_size;
    p_dfu_ctx->retry_count     = DEFAULT_RETRIES;
    p_dfu_ctx->block_num       = (p_res->select.offset / DEFAULT_BLOCK_SIZE);
    p_dfu_ctx->max_obj_size    = p_res->select.max_size;

    background_dfu_transport_state_update(p_dfu_ctx);

    block_manager_init(&p_dfu_ctx->block_manager,
                       p_dfu_ctx->dfu_state,
                       *p_dfu_ctx->p_resource_size,
                       p_dfu_ctx->block_num,
                       dfu_block_manager_result_handler,
                       p_dfu_ctx);

    UNUSED_RETURN_VALUE(background_dfu_handle_event(p_dfu_ctx, BACKGROUND_DFU_EVENT_TRANSFER_CONTINUE));
}

/***************************************************************************************************
 * @section Timer handlers
 **************************************************************************************************/

/**@brief Handler function for block request timer.
 *
 * @param[inout] p_context DFU context.
 */
static void block_request_handler(void * p_context)
{
    background_dfu_context_t * p_dfu_ctx = (background_dfu_context_t *)p_context;

    if ((p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE) &&
        (p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE))
    {
        return;
    }

    background_dfu_request_bitmap_t req_bmp;
    if (block_manager_request_bitmap_get(&p_dfu_ctx->block_manager, &req_bmp) &&
        (req_bmp.size > 0))
    {
        background_dfu_transport_block_request_send(p_dfu_ctx, &req_bmp);
    }

    // Reschedule the timer.
    uint32_t jitter = block_request_jitter_get();
    uint32_t err_code = app_timer_start(m_missing_block_timer, APP_TIMER_TICKS(jitter), p_dfu_ctx);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in app_timer_start (%d)", err_code);
    }
}

/**@brief Handler function for block timeout timer.
 *
 * @param[inout] p_context DFU context.
 */
static void block_timeout_handler(void * p_context)
{
    background_dfu_context_t * p_dfu_ctx = (background_dfu_context_t *)p_context;

    NRF_LOG_INFO("Block timeout! (b: %d)",
            block_manager_get_current_block(&p_dfu_ctx->block_manager));

    if ((p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE) &&
        (p_dfu_ctx->dfu_state != BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE))
    {
        return;
    }

    if (block_manager_increment_current_block(&p_dfu_ctx->block_manager))
    {
        start_block_timeout_timer(p_dfu_ctx);
    }
}

/***************************************************************************************************
 * @section API functions
 **************************************************************************************************/

/** @brief Helper function converting DFU state to string.
 *
 *  @param[in] state DFU client state.
 *
 *  @return A pointer to null terminated string with state name.
 */
const char * background_dfu_state_to_string(const background_dfu_state_t state)
{
    static const char * const names[] =
    {
        "DFU_GET_MANIFEST_BLOCKWISE",
        "DFU_GET_FIRMWARE_BLOCKWISE",
        "DFU_GET_MANIFEST_METADATA",
        "DFU_WAIT_FOR_RESET",
        "DFU_IDLE",
        "DFU_ERROR",
    };

    return names[(uint32_t)state - BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE];
}

/** @brief Helper function convering DFU event name to string.
 *
 *  @param[in] state DFU client event.
 *
 *  @return A pointer to null terminated string with event name.
 */
const char * background_dfu_event_to_string(const background_dfu_event_t event)
{
    static const char * const names[] = {
        "DFU_EVENT_TRANSFER_COMPLETE",
        "DFU_EVENT_TRANSFER_CONTINUE",
        "DFU_EVENT_TRANSFER_ERROR",
        "DFU_EVENT_PROCESSING_ERROR",
    };

    return names[event];
}

uint32_t background_dfu_handle_event(background_dfu_context_t * p_dfu_ctx,
                                     background_dfu_event_t     event)
{
    uint32_t err_code = NRF_SUCCESS;

    NRF_LOG_INFO("state=%s event=%s",
                  (uint32_t)background_dfu_state_to_string(p_dfu_ctx->dfu_state),
                  (uint32_t)background_dfu_event_to_string(event));

    switch (p_dfu_ctx->dfu_state)
    {
        case BACKGROUND_DFU_IDLE:
        {
            if (event == BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE)
            {
                p_dfu_ctx->dfu_diag.prev_state = BACKGROUND_DFU_IDLE;

                p_dfu_ctx->dfu_state     = BACKGROUND_DFU_GET_MANIFEST_METADATA;
                p_dfu_ctx->block_num     = 0;
                p_dfu_ctx->retry_count   = DEFAULT_RETRIES;

                background_dfu_transport_state_update(p_dfu_ctx);
            }

            break;
        }

        case BACKGROUND_DFU_GET_MANIFEST_METADATA:
        {
            if (event == BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE)
            {
                if (!is_image_different(p_dfu_ctx))
                {
                    NRF_LOG_INFO("Image is already installed");
                    background_dfu_reset_state(p_dfu_ctx);
                    background_dfu_transport_state_update(p_dfu_ctx);
                    break;
                }

                p_dfu_ctx->dfu_diag.prev_state = BACKGROUND_DFU_GET_MANIFEST_METADATA;

                p_dfu_ctx->dfu_state = BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE;

                // Initiate init command check procedure.
                if (background_dfu_op_select(NRF_DFU_OBJ_TYPE_COMMAND,
                                             dfu_init_check_callback,
                                             p_dfu_ctx) != NRF_SUCCESS)
                {
                    NRF_LOG_ERROR("No valid init command - select error");
                    setup_download_init_command(p_dfu_ctx);
                }
                else
                {
                    // We wait for dfu request to finish - do not send anything.
                    return NRF_SUCCESS;
                }
            }

            break;
        }

        case BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE:
        {
            if (event == BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE)
            {
                p_dfu_ctx->dfu_diag.prev_state = BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE;

                if (p_dfu_ctx->dfu_mode == BACKGROUND_DFU_MODE_MULTICAST)
                {
                    stop_block_timeout_timer(p_dfu_ctx);
                }

                if (background_dfu_op_select(NRF_DFU_OBJ_TYPE_DATA,
                                             dfu_data_select_callback,
                                             p_dfu_ctx) != NRF_SUCCESS)
                {
                    NRF_LOG_ERROR("Select failed");
                    dfu_handle_error(p_dfu_ctx);
                    err_code = NRF_ERROR_INTERNAL;
                }
                else
                {
                    return NRF_SUCCESS;
                }
            }
            else if (event == BACKGROUND_DFU_EVENT_PROCESSING_ERROR)
            {
                p_dfu_ctx->dfu_diag.prev_state = BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE;

                if (p_dfu_ctx->dfu_mode == BACKGROUND_DFU_MODE_MULTICAST)
                {
                    stop_block_timeout_timer(p_dfu_ctx);
                }

                NRF_LOG_ERROR("Processing error while downloading init command.");
                dfu_handle_error(p_dfu_ctx);
            }
            break;
        }

        case BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE:
        {
            if (event == BACKGROUND_DFU_EVENT_TRANSFER_COMPLETE)
            {
                p_dfu_ctx->dfu_diag.prev_state = BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE;

                p_dfu_ctx->dfu_state           = BACKGROUND_DFU_WAIT_FOR_RESET;

                if (p_dfu_ctx->dfu_mode == BACKGROUND_DFU_MODE_MULTICAST)
                {
                    stop_block_timeout_timer(p_dfu_ctx);
                }

                background_dfu_transport_state_update(p_dfu_ctx);
            }
            else if (event == BACKGROUND_DFU_EVENT_PROCESSING_ERROR)
            {
                p_dfu_ctx->dfu_diag.prev_state = BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE;

                if (p_dfu_ctx->dfu_mode == BACKGROUND_DFU_MODE_MULTICAST)
                {
                    stop_block_timeout_timer(p_dfu_ctx);
                }

                NRF_LOG_ERROR("Processing error while downloading firmware.");
                dfu_handle_error(p_dfu_ctx);
            }
            break;
        }

        case BACKGROUND_DFU_WAIT_FOR_RESET:
            NRF_LOG_WARNING("An event received in wait for reset state. This should not happen.");
            break;

        default:
            NRF_LOG_ERROR("Unhandled state");
            break;
    }

    if ((p_dfu_ctx->dfu_state != BACKGROUND_DFU_IDLE) &&
        (p_dfu_ctx->dfu_state != BACKGROUND_DFU_ERROR) &&
        (p_dfu_ctx->dfu_state != BACKGROUND_DFU_WAIT_FOR_RESET))
    {
        if (((p_dfu_ctx->dfu_state == BACKGROUND_DFU_GET_FIRMWARE_BLOCKWISE) ||
             (p_dfu_ctx->dfu_state == BACKGROUND_DFU_GET_MANIFEST_BLOCKWISE)) &&
             (p_dfu_ctx->dfu_mode  == BACKGROUND_DFU_MODE_MULTICAST))
        {
            // In multicast DFU firmware download, client doesn't initiate block requests.
        }
        else
        {
            if ((event == BACKGROUND_DFU_EVENT_TRANSFER_ERROR) && (p_dfu_ctx->retry_count > 0))
            {
                p_dfu_ctx->retry_count -= 1;
            }

            if (p_dfu_ctx->retry_count > 0)
            {
                background_dfu_transport_send_request(p_dfu_ctx);
            }
            else
            {
                NRF_LOG_ERROR("No more retries");
                dfu_handle_error(p_dfu_ctx);
            }
        }
    }

    return err_code;
}

void background_dfu_reset_state(background_dfu_context_t * p_dfu_ctx)
{
    sha256_context_t sha256_ctx;

    uint8_t  hash[32];
    uint32_t err_code = NRF_SUCCESS;

    p_dfu_ctx->dfu_state      = BACKGROUND_DFU_IDLE;
    p_dfu_ctx->dfu_mode       = BACKGROUND_DFU_MODE_UNICAST;
    p_dfu_ctx->suit_manifest_size  = 0;
    p_dfu_ctx->firmware_size  = 0;
    p_dfu_ctx->remaining_size = 0;

    memset(&p_dfu_ctx->dfu_diag, 0, sizeof(p_dfu_ctx->dfu_diag));

    err_code = sha256_init(&sha256_ctx);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in sha256_init (%d)", err_code);
    }

    err_code = sha256_update(&sha256_ctx, (const uint8_t *)DFU_DATE_TIME, strlen(DFU_DATE_TIME));
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in sha256_update (%d)", err_code);
    }

    err_code = sha256_final(&sha256_ctx, (uint8_t *)hash, false);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in sha256_final (%d)", err_code);
    }

    p_dfu_ctx->dfu_diag.build_id   = uint32_big_decode(hash);
    p_dfu_ctx->dfu_diag.state      = BACKGROUND_DFU_IDLE;
    p_dfu_ctx->dfu_diag.prev_state = BACKGROUND_DFU_IDLE;

    NRF_LOG_INFO("Current DFU Diag version: %s, 0x%08x",
            (uint32_t)DFU_DATE_TIME, p_dfu_ctx->dfu_diag.build_id);
}

void background_dfu_state_init(background_dfu_context_t * p_dfu_ctx)
{
    uint32_t err_code;

    err_code = app_timer_create(&m_missing_block_timer,
                                APP_TIMER_MODE_SINGLE_SHOT,
                                block_request_handler);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in app_timer_create (%d)", err_code);
    }

    err_code = app_timer_create(&m_block_timeout_timer,
                                APP_TIMER_MODE_SINGLE_SHOT,
                                block_timeout_handler);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Error in app_timer_create (%d)", err_code);
    }

    background_dfu_reset_state(p_dfu_ctx);
}
