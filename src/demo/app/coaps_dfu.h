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

struct background_dfu_diagnostic;

/** @brief Initialize DFU client.
 *
 *  @param[in] Application context for CoAP.
 *
 *  @return NRF_SUCCESS on success, otherwise an error code is returned.
 */
uint32_t coaps_dfu_init(const void * p_context);

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
