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
#include <stdbool.h>
#include "nrf_dfu_types.h"
#include "nrf_dfu_settings.h"
#include "nrf_dfu_utils.h"
#include "nrf_bootloader_info.h"
#include "nrf_crypto.h"
#include "nrf_assert.h"
#include "nrf_dfu_ver_validation.h"

#define NRF_LOG_MODULE_NAME nrf_dfu_ver_validation
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();


/** @brief Macro for reading the Firmware ID of a SoftDevice at a given base address.
 */
#ifndef _SD_FWID_GET
#define _SD_FWID_GET(baseaddr)         SD_OFFSET_GET_UINT16(baseaddr, 0x0C)
#endif

#define EXT_ERR(err) (nrf_dfu_result_t)((uint32_t)NRF_DFU_RES_CODE_EXT_ERROR + (uint32_t)err)

static bool fw_hash_type_ok(suit_component_t const * p_component)
{
    ASSERT(p_component != NULL);
    return (p_component->digest_alg == suit_digest_alg_sha256);
}

#ifndef NRF_DFU_APP_ACCEPT_SAME_VERSION
#define NRF_DFU_APP_ACCEPT_SAME_VERSION 1
#endif

static bool fw_version_ok(suit_context_t const * p_suit_ctx)
{
    ASSERT(p_suit_ctx != NULL);

    if (p_suit_ctx->version == s_dfu_settings.app_version)
    {
        return NRF_DFU_APP_ACCEPT_SAME_VERSION;
    }
    else if (p_suit_ctx->version < s_dfu_settings.app_version)
    {
        return false;
    }

    return true;
}

nrf_dfu_result_t nrf_dfu_ver_validation_check(suit_context_t const * p_suit_ctx)
{
    if (!fw_version_ok(p_suit_ctx))
    {
        NRF_LOG_WARNING("FW version too low.");
        return EXT_ERR(NRF_DFU_EXT_ERROR_FW_VERSION_FAILURE);
    }

    uint8_t m_class_id[]  = SUIT_CLASS_ID;
    uint8_t m_vendor_id[] = SUIT_VENDOR_ID;

    // Iterate through all the components in the manifest.
    for (int idx = 0; idx < p_suit_ctx->component_count; idx++)
    {
        if (!fw_hash_type_ok(&p_suit_ctx->components[idx]))
        {
            NRF_LOG_ERROR("Invalid hash type.");
            return EXT_ERR(NRF_DFU_EXT_ERROR_WRONG_HASH_TYPE);
        }

        else if (!NRF_DFU_DEBUG)
        {
            if (p_suit_ctx->components[idx].len_class_id == 0)
            {
                NRF_LOG_ERROR("SUIT manifest: no class ID.");
                return EXT_ERR(NRF_DFU_EXT_ERROR_SUIT_MANIFEST_INVALID);
            }
            else if (!suit_match_class_id(p_suit_ctx, idx,
                     (uint8_t *)m_class_id, sizeof(m_class_id)))
            {
                NRF_LOG_ERROR("SUIT manifest: class ID mismatch.");
                return EXT_ERR(NRF_DFU_EXT_ERROR_HW_VERSION_FAILURE);
            }
            else if (p_suit_ctx->components[idx].len_vendor_id == 0)
            {
                NRF_LOG_ERROR("SUIT manifest: no vendor ID.");
                return EXT_ERR(NRF_DFU_EXT_ERROR_SUIT_MANIFEST_INVALID);
            }
            else if (!suit_match_vendor_id(p_suit_ctx, idx,
                     (uint8_t *)m_vendor_id, sizeof(m_class_id)))
            {
                NRF_LOG_ERROR("SUIT manifest: vendor ID mismatch.");
                return EXT_ERR(NRF_DFU_EXT_ERROR_HW_VERSION_FAILURE);
            }

        }
    }

    return NRF_DFU_RES_CODE_SUCCESS;
}
