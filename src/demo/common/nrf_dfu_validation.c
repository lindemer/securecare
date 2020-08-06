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
#include "nrf_dfu_flash.h"
#include "nrf_bootloader_info.h"
#include "crc32.h"
#include "nrf_crypto.h"
#include "nrf_crypto_shared.h"
#include "nrf_assert.h"
#include "nrf_dfu_validation.h"
#include "nrf_dfu_ver_validation.h"
#include "nrf_strerror.h"

#define NRF_LOG_MODULE_NAME nrf_dfu_validation
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
NRF_LOG_MODULE_REGISTER();

#define DFU_REQUIRES_SOFTDEVICE 0

#define EXT_ERR(err) (nrf_dfu_result_t)((uint32_t)NRF_DFU_RES_CODE_EXT_ERROR + (uint32_t)err)

/* Whether a complete SUIT manifest has been received and prevalidated, but the firmware
 * is not yet fully transferred. This value will also be correct after reset.
 */
static bool               m_valid_manifest_present = false;

static suit_context_t     m_suit_ctx;

__ALIGN(4) extern const uint8_t pk[64];

/** @brief Value length structure holding the public key.
 *
 * @details The pk value pointed to is the public key present in dfu_public_key.c
 */
static nrf_crypto_ecc_public_key_t                  m_public_key;

/** @brief Structure to hold the hash for the firmware image
 */
static nrf_crypto_hash_sha256_digest_t              m_fw_hash;

/** @brief Whether nrf_crypto and local keys have been initialized.
 */
static bool                                         m_crypto_initialized = false;

/** @brief Flag used by parser code to indicate that the manifest has been found to be invalid.
 */
static bool                                         m_manifest_valid = false;

static void crypto_init(void)
{
    ret_code_t err_code;
    uint8_t    pk_copy[sizeof(pk)];

    if (m_crypto_initialized)
    {
        return;
    }

    err_code = nrf_crypto_init();
    ASSERT(err_code == NRF_SUCCESS);
    UNUSED_PARAMETER(err_code);

    // Convert public key to big-endian format for use in nrf_crypto.
    nrf_crypto_internal_double_swap_endian(pk_copy, pk, sizeof(pk) / 2);

    err_code = nrf_crypto_ecc_public_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                  &m_public_key,
                                                  pk_copy,
                                                  sizeof(pk));
    ASSERT(err_code == NRF_SUCCESS);
    UNUSED_PARAMETER(err_code);

    m_crypto_initialized = true;
}

bool nrf_dfu_validation_manifest_decode()
{
    crypto_init();

    const uint8_t * env = s_dfu_settings.suit_manifest;
    uint32_t len = s_dfu_settings.progress.manifest_size;

    uint32_t err;
    uint8_t * man;
    size_t len_man;

    // Verify manifest signature
    if ((err = suit_raw_unwrap(&m_public_key, env, len, (const uint8_t **)&man, &len_man)))
    {
        NRF_LOG_ERROR("Manifest signature check failed (0x%x)", err);
        return false;
    }
    else
    {
        // Parse manifest contents.
        if ((err = suit_parse(&m_suit_ctx, (const uint8_t *)man, len_man)))
	{
            NRF_LOG_ERROR("Manifest parse failed (0x%x)", err);
	    return false;
	}
    }

    m_manifest_valid = true;

    return true;
}

void nrf_dfu_validation_init(void)
{
    // If the manifest is stored to flash, it was already validated.
    if ((s_dfu_settings.progress.manifest_size != 0) &&
         nrf_dfu_validation_manifest_decode())
    {
        NRF_LOG_INFO("Valid manifest found in flash.")
        m_valid_manifest_present = true;
    }
    else
    {
        NRF_LOG_INFO("No manifest found in flash.")
        m_valid_manifest_present = false;
    }
}

nrf_dfu_result_t nrf_dfu_validation_manifest_create(uint32_t size)
{
    nrf_dfu_result_t ret_val = NRF_DFU_RES_CODE_SUCCESS;
    if (size == 0)
    {
        ret_val = NRF_DFU_RES_CODE_INVALID_PARAMETER;
    }
    else if (size > SUIT_MANIFEST_MAX_SIZE)
    {
        ret_val = NRF_DFU_RES_CODE_INSUFFICIENT_RESOURCES;
    }
    else
    {
        // Set DFU to uninitialized.
        m_valid_manifest_present = false;

        // Reset all progress.
        nrf_dfu_settings_progress_reset();

        // Set the SUIT manifest size.
        s_dfu_settings.progress.manifest_size = size;
    }
    return ret_val;
}


nrf_dfu_result_t nrf_dfu_validation_manifest_append(uint8_t const * p_data, uint32_t length)
{
    nrf_dfu_result_t ret_val = NRF_DFU_RES_CODE_SUCCESS;
    if ((length + s_dfu_settings.progress.manifest_offset) > s_dfu_settings.progress.manifest_size)
    {
        NRF_LOG_ERROR("SUIT manifest larger than expected.");
        ret_val = NRF_DFU_RES_CODE_INVALID_PARAMETER;
    }
    else
    {
        // Copy the received data to RAM, update offset and calculate CRC.
        memcpy(&s_dfu_settings.suit_manifest[s_dfu_settings.progress.manifest_offset],
                p_data,
                length);

        s_dfu_settings.progress.manifest_offset += length;
        s_dfu_settings.progress.manifest_crc = crc32_compute(p_data,
                                                            length,
                                                            &s_dfu_settings.progress.manifest_crc);
    }
    return ret_val;
}


void nrf_dfu_validation_suit_manifest_status_get(uint32_t * p_offset,
                                            uint32_t * p_crc,
                                            uint32_t * p_max_size)
{
    *p_offset   = s_dfu_settings.progress.manifest_offset;
    *p_crc      = s_dfu_settings.progress.manifest_crc;
    *p_max_size = SUIT_MANIFEST_MAX_SIZE;
}


bool nrf_dfu_validation_suit_manifest_present(void)
{
    return m_valid_manifest_present;
}

nrf_dfu_result_t nrf_dfu_validation_get_component_uri(int comp, char * uri)
{
    if (comp >= m_suit_ctx.component_count)
    {
        NRF_LOG_ERROR("Component identifier exceeds manifest content.");
        return NRF_DFU_RES_CODE_INVALID_OBJECT;
    } 

    memcpy(uri, m_suit_ctx.components[comp].uri, m_suit_ctx.components[comp].len_uri);
    uri[m_suit_ctx.components[comp].len_uri] = 0; // NULL-termination

    return NRF_SUCCESS;
}

nrf_dfu_result_t nrf_dfu_validation_get_component_size(int comp, uint32_t * size)
{
    if (comp >= m_suit_ctx.component_count)
    {
        NRF_LOG_ERROR("Component identifier exceeds manifest content.");
        return NRF_DFU_RES_CODE_INVALID_OBJECT;
    }
    
    *size = m_suit_ctx.components[comp].size;

    return NRF_SUCCESS;
}

// Function to calculate the total size of the firmware(s) in the update.
static nrf_dfu_result_t update_data_size_get(suit_context_t const * p_suit_ctx, uint32_t * p_size)
{
    nrf_dfu_result_t ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_SUIT_MANIFEST_INVALID);
    uint32_t         fw_sz   = 0;

    for (size_t idx = 0; idx < SUIT_MAX_COMPONENTS; idx++)
    {
        fw_sz += p_suit_ctx->components[idx].size;
    }

    if (fw_sz)
    {
        *p_size = fw_sz;
        ret_val = NRF_DFU_RES_CODE_SUCCESS;
    }
    else
    {
        NRF_LOG_ERROR("SUIT manifest does not contain valid firmware size.");
    }

    return ret_val;
}


/**
 * @brief Function to check if single bank update should be used.
 *
 * @param new_fw_type Firmware type.
 */
static bool use_single_bank(suit_context_t const * p_suit_ctx)
{
    return false;
}


// Function to determine whether the new firmware needs a SoftDevice to be present.
static bool update_requires_softdevice(suit_context_t const * p_suit_ctx)
{
    return false;
}


// Function to determine whether the SoftDevice can be removed during the update or not.
static bool keep_softdevice(suit_context_t const * p_suit_ctx)
{
    UNUSED_PARAMETER(p_suit_ctx); // It's unused when DFU_REQUIRES_SOFTDEVICE is true.
    return DFU_REQUIRES_SOFTDEVICE || update_requires_softdevice(p_suit_ctx);
}


/**@brief Function to determine where to temporarily store the incoming firmware.
 *        This also checks whether the update will fit, and deletes existing
 *        firmware to make room for the new firmware.
 *
 * @param[in]  p_suit_ctx    SUIT manifest.
 * @param[in]  fw_size  The size of the incoming firmware.
 * @param[out] p_addr   The address at which to initially store the firmware.
 *
 * @retval NRF_DFU_RES_CODE_SUCCESS                 If the size check passed and
 *                                                  an address was found.
 * @retval NRF_DFU_RES_CODE_INSUFFICIENT_RESOURCES  If the size check failed.
 */
static nrf_dfu_result_t update_data_addr_get(suit_context_t const * p_suit_ctx,
                                             uint32_t               fw_size,
                                             uint32_t             * p_addr)
{
    nrf_dfu_result_t ret_val = NRF_DFU_RES_CODE_SUCCESS;
    ret_code_t err_code = nrf_dfu_cache_prepare(fw_size,
                                                use_single_bank(p_suit_ctx),
                                                NRF_DFU_FORCE_DUAL_BANK_APP_UPDATES,
                                                keep_softdevice(p_suit_ctx));
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Can't find room for update");
        ret_val = NRF_DFU_RES_CODE_INSUFFICIENT_RESOURCES;
    }
    else
    {
        *p_addr = nrf_dfu_bank1_start_addr();
        NRF_LOG_DEBUG("Write address set to 0x%08x", *p_addr);
    }
    return ret_val;
}


nrf_dfu_result_t nrf_dfu_validation_prevalidate(void)
{
    nrf_dfu_result_t                 ret_val        = NRF_DFU_RES_CODE_SUCCESS;
    
    // Validate versions.
    if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
    {
        ret_val = nrf_dfu_ver_validation_check(&m_suit_ctx);
    }

    if (ret_val != NRF_DFU_RES_CODE_SUCCESS)
    {
        NRF_LOG_WARNING("Prevalidation failed.");
    }

    return ret_val;
}


nrf_dfu_result_t nrf_dfu_validation_suit_manifest_execute(uint32_t * p_dst_data_addr,
                                                          uint32_t * p_data_len)
{
    nrf_dfu_result_t ret_val = NRF_DFU_RES_CODE_SUCCESS;

    if (s_dfu_settings.progress.manifest_offset != s_dfu_settings.progress.manifest_size)
    {
        // The object wasn't the right (requested) size.
        NRF_LOG_ERROR("Execute with faulty offset");
        ret_val = NRF_DFU_RES_CODE_OPERATION_NOT_PERMITTED;
    }
    else if (m_valid_manifest_present)
    {
        *p_dst_data_addr = nrf_dfu_bank1_start_addr();
        ret_val          = update_data_size_get(&m_suit_ctx, p_data_len);
    }
    else if (nrf_dfu_validation_manifest_decode())
    {
        // Will only get here if SUIT manifest was received since last reset.
        // An SUIT manifest should not be written to flash until after it's been checked here.
        ret_val = nrf_dfu_validation_prevalidate();

        *p_dst_data_addr = 0;
        *p_data_len      = 0;

        // Get size of binary.
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            ret_val = update_data_size_get(&m_suit_ctx, p_data_len);
        }

        // Get address where to flash the binary.
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            ret_val = update_data_addr_get(&m_suit_ctx, *p_data_len, p_dst_data_addr);
        }

        // Set flag validating the SUIT manifest.
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            m_valid_manifest_present = true;
        }
        else
        {
            nrf_dfu_settings_progress_reset();
        }
    }
    else
    {
        NRF_LOG_ERROR("Failed to decode SUIT manifest.");
        ret_val = NRF_DFU_RES_CODE_INVALID_OBJECT;
    }

    return ret_val;
}


// Function to check the hash received in the SUIT manifest against the received firmware.
// little_endian specifies the endianness of @p p_hash.
static bool nrf_dfu_validation_hash_ok(uint8_t const * p_hash, uint32_t src_addr, uint32_t data_len, bool little_endian)
{
    ret_code_t err_code;
    bool       result   = true;
    uint8_t    hash_be[NRF_CRYPTO_HASH_SIZE_SHA256];
    size_t     hash_len = NRF_CRYPTO_HASH_SIZE_SHA256;

    nrf_crypto_hash_context_t hash_context = {0};

    crypto_init();

    if (little_endian)
    {
        // Convert to hash to big-endian format for use in nrf_crypto.
        nrf_crypto_internal_swap_endian(hash_be,
                                        p_hash,
                                        NRF_CRYPTO_HASH_SIZE_SHA256);
        p_hash = hash_be;
    }

    NRF_LOG_DEBUG("Hash verification. start address: 0x%x, size: 0x%x",
                  src_addr,
                  data_len);

    err_code = nrf_crypto_hash_calculate(&hash_context,
                                         &g_nrf_crypto_hash_sha256_info,
                                         (uint8_t*)src_addr,
                                         data_len,
                                         m_fw_hash,
                                         &hash_len);

    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Could not run hash verification (err_code 0x%x).", err_code);
        result = false;
    }
    else if (memcmp(m_fw_hash, p_hash, NRF_CRYPTO_HASH_SIZE_SHA256) != 0)
    {
        NRF_LOG_WARNING("Hash verification failed.");
        NRF_LOG_DEBUG("Expected FW hash:")
        NRF_LOG_HEXDUMP_DEBUG(p_hash, NRF_CRYPTO_HASH_SIZE_SHA256);
        NRF_LOG_DEBUG("Actual FW hash:")
        NRF_LOG_HEXDUMP_DEBUG(m_fw_hash, NRF_CRYPTO_HASH_SIZE_SHA256);
        NRF_LOG_FLUSH();

        result = false;
    }

    return result;
}


// Function to check the hash received in the SUIT manifest against the received firmware.
bool fw_hash_ok(suit_context_t const * p_suit_ctx, uint32_t fw_start_addr, uint32_t fw_size)
{
    // FIXME: Only handles one component.
    ASSERT(p_suit_ctx != NULL);
    return nrf_dfu_validation_hash_ok(p_suit_ctx->components[0].digest, fw_start_addr, fw_size, false);
}

static bool boot_validation_extract(boot_validation_t * p_boot_validation,
                                    suit_context_t const * p_suit_ctx,
                                    uint32_t index,
                                    uint32_t start_addr,
                                    uint32_t data_len,
                                    boot_validation_type_t default_type)
{
    ret_code_t err_code;
    size_t     hash_len = NRF_CRYPTO_HASH_SIZE_SHA256;

    nrf_crypto_hash_context_t hash_context = {0};

    memset(p_boot_validation, 0, sizeof(boot_validation_t));
    p_boot_validation->type = default_type;

    switch(p_boot_validation->type)
    {
        case NO_VALIDATION:
            break;

        case VALIDATE_SHA256:
            err_code = nrf_crypto_hash_calculate(&hash_context,
                                                 &g_nrf_crypto_hash_sha256_info,
                                                 (uint8_t*)start_addr,
                                                 data_len,
                                                 p_boot_validation->bytes,
                                                 &hash_len);
            if (err_code != NRF_SUCCESS)
            {
                NRF_LOG_ERROR("nrf_crypto_hash_calculate() failed with error %s", nrf_strerror_get(err_code));
                return false;
            }
            break;

        default:
            NRF_LOG_ERROR("Invalid boot validation type: %d", p_boot_validation->type);
            return false;
    }

    return nrf_dfu_validation_boot_validate(p_boot_validation, start_addr, data_len);
}


// The is_trusted argument specifies whether the function should have side effects.
static bool postvalidate_app(suit_context_t const * p_suit_ctx, uint32_t src_addr, uint32_t data_len, bool is_trusted)
{
    boot_validation_t boot_validation;

    if (!boot_validation_extract(&boot_validation, p_suit_ctx, 0, src_addr, data_len, VALIDATE_SHA256))
    {
        return false;
    }

    if (!is_trusted)
    {
        return true;
    }

    memcpy(&s_dfu_settings.boot_validation_app, &boot_validation, sizeof(boot_validation));

    s_dfu_settings.bank_1.bank_code = NRF_DFU_BANK_VALID_APP;

    NRF_LOG_DEBUG("Invalidating old application in bank 0.");
    s_dfu_settings.bank_0.bank_code = NRF_DFU_BANK_INVALID;

    if (!NRF_DFU_DEBUG)
    {
        s_dfu_settings.app_version = p_suit_ctx->sequence_number;
    }

    return true;
}

bool nrf_dfu_validation_boot_validate(boot_validation_t const * p_validation, uint32_t data_addr, uint32_t data_len)
{
    uint8_t const * p_data = (uint8_t*) data_addr;
    switch(p_validation->type)
    {
        case NO_VALIDATION:
            return true;

        case VALIDATE_CRC:
        {
            uint32_t current_crc = *(uint32_t *)p_validation->bytes;
            uint32_t crc = crc32_compute(p_data, data_len, NULL);

            if (crc != current_crc)
            {
                // CRC does not match with what is stored.
                NRF_LOG_DEBUG("CRC check of app failed. Return %d", NRF_DFU_DEBUG);
                return NRF_DFU_DEBUG;
            }
            return true;
        }

        case VALIDATE_SHA256:
            return nrf_dfu_validation_hash_ok(p_validation->bytes, data_addr, data_len, false);

        default:
            ASSERT(false);
            return false;
    }
}


nrf_dfu_result_t postvalidate(uint32_t data_addr, uint32_t data_len, bool is_trusted)
{
    nrf_dfu_result_t           ret_val = NRF_DFU_RES_CODE_SUCCESS;

    if (!fw_hash_ok(&m_suit_ctx, data_addr, data_len))
    {
        ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_VERIFICATION_FAILED);
    }
    else
    {
        if (!postvalidate_app(&m_suit_ctx, data_addr, data_len, is_trusted))
        {
            ret_val = NRF_DFU_RES_CODE_INVALID_OBJECT;
        }
    }

    if (!is_trusted)
    {
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            s_dfu_settings.bank_current = NRF_DFU_CURRENT_BANK_1;
        }
        else
        {
            nrf_dfu_settings_progress_reset();
        }
    }
    else
    {
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            // Mark the update as complete and valid.
            s_dfu_settings.bank_1.image_crc  = crc32_compute((uint8_t *)data_addr, data_len, NULL);
            s_dfu_settings.bank_1.image_size = data_len;
        }
        else
        {
            nrf_dfu_bank_invalidate(&s_dfu_settings.bank_1);
        }

        nrf_dfu_settings_progress_reset();
        s_dfu_settings.progress.update_start_address = data_addr;
    }

    return ret_val;
}


nrf_dfu_result_t nrf_dfu_validation_post_data_execute(uint32_t data_addr, uint32_t data_len)
{
    return postvalidate(data_addr, data_len, false);
}


nrf_dfu_result_t nrf_dfu_validation_activation_prepare(uint32_t data_addr, uint32_t data_len)
{
    return postvalidate(data_addr, data_len, true);
}


bool nrf_dfu_validation_valid_external_app(void)
{
    return s_dfu_settings.bank_1.bank_code == NRF_DFU_BANK_VALID_EXT_APP;
}
