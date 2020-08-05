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

static bool fw_hash_type_ok(suit_context_t const * p_suit_ctx)
{
    // FIXME
    return true;

    /*
    ASSERT(p_suit_ctx != NULL);

    return (p_suit_ctx->hash.hash_type == DFU_HASH_TYPE_SHA256);
    */
}


/*
static bool fw_version_required(suit_context_t const * p_suit_ctx)
{
    bool result = true;

    if (new_fw_type == DFU_FW_TYPE_SOFTDEVICE)
    {
        result = false; // fw_version is optional in SoftDevice updates. If present, it will be checked against the app version.
    }
    else if (new_fw_type == DFU_FW_TYPE_APPLICATION)
    {
        result = NRF_DFU_APP_DOWNGRADE_PREVENTION; // fw_version is configurable in app updates.
    }
#if NRF_DFU_SUPPORTS_EXTERNAL_APP
#if !NRF_DFU_EXTERNAL_APP_VERSIONING
    else if (new_fw_type == DFU_FW_TYPE_EXTERNAL_APPLICATION)
    {
        return false;
    }
#endif //!NRF_DFU_EXTERNAL_APP_VERSIONING
#endif // NRF_DFU_SUPPORTS_EXTERNAL_APP

    return result;
}
*/


static bool fw_type_ok(suit_context_t const * p_suit_ctx)
{
    ASSERT(p_suit_ctx != NULL);

    // FIXME
    return true;

    /*
    return ((p_suit_ctx->has_type)
            && (  (p_suit_ctx->type == DFU_FW_TYPE_APPLICATION)
               || (p_suit_ctx->type == DFU_FW_TYPE_SOFTDEVICE)
               || (p_suit_ctx->type == DFU_FW_TYPE_BOOTLOADER)
               || (p_suit_ctx->type == DFU_FW_TYPE_SOFTDEVICE_BOOTLOADER)
#if NRF_DFU_SUPPORTS_EXTERNAL_APP
               || (p_suit_ctx->type == DFU_FW_TYPE_EXTERNAL_APPLICATION)
#endif // NRF_DFU_SUPPORTS_EXTERNAL_APP
            ));
    */

}


#ifndef NRF_DFU_APP_ACCEPT_SAME_VERSION
#define NRF_DFU_APP_ACCEPT_SAME_VERSION 1
#endif


/*
// This function assumes p_suit_ctx->has_fw_version.
static bool fw_version_ok(suit_context_t const * p_suit_ctx)
{
    ASSERT(p_suit_ctx != NULL);
    ASSERT(p_suit_ctx->has_fw_version);

    if ((p_suit_ctx->type == DFU_FW_TYPE_APPLICATION) ||
        (p_suit_ctx->type == DFU_FW_TYPE_SOFTDEVICE))
    {
        if (!NRF_DFU_APP_DOWNGRADE_PREVENTION)
        {
            return true;
        }
        else if ((p_suit_ctx->fw_version > s_dfu_settings.app_version))
        {
            return true;
        }
        else if ((p_suit_ctx->fw_version == s_dfu_settings.app_version))
        {
            return NRF_DFU_APP_ACCEPT_SAME_VERSION;
        }
        else
        {
            return false;
        }
    }
#if NRF_DFU_SUPPORTS_EXTERNAL_APP
#if NRF_DFU_EXTERNAL_APP_VERSIONING
    else if (p_suit_ctx->type == DFU_FW_TYPE_EXTERNAL_APPLICATION)
    {
        return (p_suit_ctx->fw_version >= s_dfu_settings.app_version);
    }
#else
    else if(p_suit_ctx->type == DFU_FW_TYPE_EXTERNAL_APPLICATION)
    {
        return true;
    }
#endif // NRF_DFU_EXTERNAL_APP_VERSIONING
#endif // NRF_DFU_SUPPORTS_EXTERNAL_APP
    else
    {
        return  (p_suit_ctx->fw_version > s_dfu_settings.bootloader_version);
    }
}
*/


nrf_dfu_result_t nrf_dfu_ver_validation_check(suit_context_t const * p_suit_ctx)
{
    nrf_dfu_result_t ret_val = NRF_DFU_RES_CODE_SUCCESS;
    if (!fw_type_ok(p_suit_ctx))
    {
        NRF_LOG_ERROR("Invalid firmware type.");
        ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_SUIT_MANIFEST_INVALID);
    }
    else if (!fw_hash_type_ok(p_suit_ctx))
    {
        NRF_LOG_ERROR("Invalid hash type.");
        ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_WRONG_HASH_TYPE);
    }

    // FIXME

    /*
    else if (!NRF_DFU_DEBUG)
    {
        if (p_suit_ctx->has_hw_version == false)
        {
            NRF_LOG_ERROR("No HW version.");
            ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_SUIT_MANIFEST_INVALID);
        }
        else if (p_suit_ctx->hw_version != NRF_DFU_HW_VERSION)
        {
            NRF_LOG_WARNING("Faulty HW version.");
            ret_val = EXT_ERR( NRF_DFU_EXT_ERROR_HW_VERSION_FAILURE);
        }

        else if (p_suit_ctx->has_fw_version)
        {
            if (!fw_version_ok(p_suit_ctx))
            {
                NRF_LOG_WARNING("FW version too low.");
                ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_FW_VERSION_FAILURE);
            }
        }
        else
        {
            if (fw_version_required(p_suit_ctx->type))
            {
                NRF_LOG_ERROR("FW version missing.");
                ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_SUIT_MANIFEST_INVALID);
            }
        }
    }
    */

    return ret_val;
}
