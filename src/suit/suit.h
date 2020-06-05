/**
 * Copyright (c) 2020, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **/

#ifndef SUIT_H
#define SUIT_H

#include "cose.h"

#define SUIT_MAX_COMPONENTS 2

/** 
 * @brief SUIT API
 * @{
 */

typedef enum {
    suit_digest_alg_sha224 = 1,
    suit_digest_alg_sha256 = 2,
    suit_digest_alg_sha384 = 3,
    suit_digest_alg_sha512 = 4,
    suit_digest_alg_sha3_224 = 5,
    suit_digest_alg_sha3_256 = 6,
    suit_digest_alg_sha3_384 = 7,
    suit_digest_alg_sha3_512 = 8,
} suit_digest_alg_t;

typedef enum {
    suit_archive_info_alg = 1,
    suit_archive_info_params = 2,
} suit_archive_info_t;

typedef enum {
    suit_archive_alg_gzip = 1,
    suit_archive_alg_bzip2 = 2,
    suit_archive_alg_deflate = 3,
    suit_archive_alg_lz4 = 4,
    suit_archive_alg_lzma = 7,
} suit_archive_alg_t;

typedef enum {
    suit_unpack_info_alg = 1,
    suit_unpack_info_params = 2,
} suit_unpack_info_t;

typedef enum {
    suit_unpack_alg_delta = 1,
    suit_unpack_alg_hex = 2,
    suit_unpack_alg_elf = 3,
} suit_unpack_alg_t;

typedef enum {
    suit_envelope_delegation = 1,
    suit_envelope_authentication_wrapper = 2,
    suit_envelope_manifest = 3,
    suit_envelope_manifest_encrypt_info = 4,
    suit_envelope_manifest_encrypted = 5,
} suit_envelope_t;

typedef enum {
    suit_header_manifest_version = 1,
    suit_header_manifest_seq_num = 2,
    suit_header_common = 3,
    suit_header_reference_uri = 4,
    suit_header_dep_resolution = 7,
    suit_header_payload_fetch = 8,
    suit_header_install = 9,
    suit_header_validate = 10,
    suit_header_load = 11,
    suit_header_run = 12,
    suit_header_text = 13,
    suit_header_coswid = 14,
} suit_header_t;

typedef enum {
    suit_common_deps = 1,
    suit_common_comps = 2,
    suit_common_dep_comps = 3,
    suit_common_seq = 4,
} suit_common_t;

typedef enum {
    suit_dep_digest = 1,
    suit_dep_prefix = 2,
} suit_dep_t;

typedef enum {
    suit_comp_id = 1,
    suit_comp_dep_idx = 2,
} suit_comp_t;

typedef enum {
    suit_cond_vendor_id = 1,
    suit_cond_class_id = 2,
    suit_cond_image_match = 3,
    suit_cond_use_before = 4,
    suit_cond_comp_offset = 5,
    suit_cond_device_id = 24,
    suit_cond_image_not_match = 25,
    suit_cond_min_battery = 26,
    suit_cond_update_authorized = 27,
    suit_cond_version = 28,
} suit_cond_t;

typedef enum {
    suit_cond_version_gt = 1,
    suit_cond_version_ge = 2,
    suit_cond_version_eq = 3,
    suit_cond_version_le = 4,
    suit_cond_version_lt = 5,
} suit_cond_version_t;

typedef enum {
    suit_dir_set_comp_idx = 12,
    suit_dir_set_dep_idx = 13,
    suit_dir_abort = 14,
    suit_dir_try_each = 15,
    suit_dir_do_each = 16, // TBD
    suit_dir_map_filter = 17, // TBD
    suit_dir_process_dep = 18,
    suit_dir_set_params = 19,
    suit_dir_override_params = 20,
    suit_dir_fetch = 21,
    suit_dir_copy = 22,
    suit_dir_run = 23,
    suit_dir_wait = 29,
    suit_dir_run_seq = 30,
    suit_dir_swap = 32,
} suit_dir_t;

typedef enum {
    suit_wait_authorization = 1,
    suit_wait_power = 2,
    suit_wait_network = 3,
    suit_wait_other_device_version = 4,
    suit_wait_time = 5,
    suit_wait_time_of_day = 6,
    suit_wait_day_of_week = 7,
} suit_wait_t;

typedef enum {
    suit_param_vendor_id = 1,
    suit_param_class_id = 2,
    suit_param_image_digest = 3,
    suit_param_use_before = 4,
    suit_param_comp_offset = 5,
    suit_param_strict_order = 12,
    suit_param_soft_fail = 13,
    suit_param_image_size = 14,
    suit_param_encrypt_info = 18,
    suit_param_archive_info = 19,
    suit_param_unpack_info = 20,
    suit_param_uri = 21,
    suit_param_source_comp = 22,
    suit_param_run_args = 23,
    suit_param_device_id = 24,
    suit_param_min_battery = 26,
    suit_param_update_priority = 27,
    suit_param_version = 28,
    suit_param_wait_info = 29,
} suit_param_t;

typedef enum {
    suit_text_manifest_description = 1,
    suit_text_update_description = 2,
    suit_text_vendor_name = 3,
    suit_text_model_name = 4,
    suit_text_vendor_domain = 5,
    suit_text_model_info = 6,
    suit_text_comp_description = 7,
    suit_text_manifest_json_source = 8,
    suit_text_manifest_yaml_source = 9,
    suit_text_version_deps = 10,
} suit_text_t;

typedef struct suit_component_s suit_component_t;
struct suit_component_s {
    
    bool run;      /* component is referenced by a run directive */
    uint32_t size; /* image size (bytes) */

    /**
     * These values are initialized to 0. If not 0, they should be processed accordingly by the 
     * update handler.
     **/
    suit_digest_alg_t digest_alg;       /* digest algorithm */
    suit_archive_alg_t archive_alg;     /* compression algorithm */

    /**
     * These pointers are initialized to NULL. If not NULL, they should be processed accordingly by 
     * the update handler. NB these reference locations in the encoded manifest itself.
     **/
    uint8_t * uri; size_t len_uri;
    uint8_t * digest; size_t len_digest;
    uint8_t * class_id; size_t len_class_id;
    uint8_t * vendor_id; size_t len_vendor_id;
    suit_component_t * source;

};

typedef struct {

    uint32_t version;         /* always 1 */
    uint32_t sequence_number; /* rollback protection */
    uint32_t component_count; /* may be less than maximum allowed */

    /**
     * Recipients should specify a limit to the number of manifest components (see I-D Section 5.4).
     **/
    suit_component_t components[SUIT_MAX_COMPONENTS];

} suit_context_t;

/**
 * @brief Parses the top-level CBOR map in a SUIT manifest
 *
 * @param       ctx     Pointer to SUIT parser context struct
 * @param       man     Pointer to encoded SUIT manifest
 * @param       len_man Size of manifest
 *
 * @retval      0       pass
 * @retval      1       fail 
 */
int suit_parse(suit_context_t * ctx,
        const uint8_t * man, size_t len_man);

/**
 * @brief Authenticate a signed SUIT envelope and return the manifest
 * 
 * @param       pem     Pointer to PEM-formatted public key string
 * @param       env     Pointer to encoded SUIT envelope
 * @param       len_env Size of envelope
 * @param[out]  man     Pointer to manifest within envelope
 * @param[out]  len_man Size of manifest
 *
 * @retval      0       pass
 * @retval      1       fail 
 */
int suit_unwrap(const char * pem, 
        const uint8_t * env, const size_t len_env,
        const uint8_t ** man, size_t * len_man);

/**
 * @brief Generate a manifest envelope with authenticated wrapper
 *
 * @param       pem     Pointer to PEM-formatted private key string
 * @param       man     Pointer to serialized SUIT manifest
 * @param       len_man Size of manifest
 * @param[out]  env     Pointer to SUIT envelope (allocated by CALLER)
 * @param[out]  len_env Size of envelope
 *
 * @retval      0       pass
 * @retval      1       fail
 */
int suit_wrap(const char * pem,
        const uint8_t * man, const size_t len_man,
        uint8_t * env, size_t * len_env);

/* API for global SUIT manifest parameters */

uint32_t suit_get_version(suit_context_t * ctx); 
uint32_t suit_get_sequence_number(suit_context_t * ctx);
uint32_t suit_get_component_count(suit_context_t * ctx);

void suit_set_version(suit_context_t * ctx, uint32_t val); 
void suit_set_sequence_number(suit_context_t * ctx, uint32_t val);
void suit_set_component_count(suit_context_t * ctx, uint32_t val);

/* API for components within a SUIT manifest */

bool suit_get_run(suit_context_t * ctx, size_t idx);
bool suit_set_run(suit_context_t * ctx, size_t idx);

uint32_t suit_get_size(suit_context_t * ctx, size_t idx);
void suit_set_size(suit_context_t * ctx, size_t idx, uint32_t val);
bool suit_has_size(suit_context_t * ctx, size_t idx);

suit_digest_alg_t suit_get_digest_alg(suit_context_t * ctx, size_t idx);
void suit_set_digest_alg(suit_context_t * ctx, size_t idx, suit_digest_alg_t val);

suit_archive_alg_t suit_get_archive_alg(suit_context_t * ctx, size_t idx);
void suit_set_archive_alg(suit_context_t * ctx, size_t idx, suit_archive_alg_t val);

bool suit_has_digest(suit_context_t * ctx, size_t idx);
bool suit_match_digest(suit_context_t * ctx, size_t idx,
        const uint8_t * digest, size_t len_digest);
void suit_get_digest(suit_context_t * ctx, size_t idx,
        const uint8_t ** digest, size_t * len_digest);
void suit_set_digest(suit_context_t * ctx, size_t idx,
        const uint8_t * digest, size_t len_digest);

bool suit_has_uri(suit_context_t * ctx, size_t idx);
void suit_get_uri(suit_context_t * ctx, size_t idx,
        const uint8_t ** uri, size_t * len_uri);
void suit_set_uri(suit_context_t * ctx, size_t idx,
        const uint8_t * uri, size_t len_uri);

bool suit_has_class_id(suit_context_t * ctx, size_t idx);
bool suit_match_class_id(suit_context_t * ctx, size_t idx,
        const uint8_t * class_id, size_t len_class_id);
void suit_get_class_id(suit_context_t * ctx, size_t idx,
        const uint8_t ** class_id, size_t * len_class_id);
void suit_set_class_id(suit_context_t * ctx, size_t idx,
        const uint8_t * class_id, size_t len_class_id);

bool suit_has_vendor_id(suit_context_t * ctx, size_t idx);
bool suit_match_vendor_id(suit_context_t * ctx, size_t idx,
        const uint8_t * vendor_id, size_t len_vendor_id);
void suit_get_vendor_id(suit_context_t * ctx, size_t idx,
        const uint8_t ** vendor_id, size_t * len_vendor_id);
void suit_set_vendor_id(suit_context_t * ctx, size_t idx,
        const uint8_t * vendor_id, size_t len_vendor_id);

bool suit_has_source_component(suit_context_t * ctx, size_t idx);
suit_component_t * suit_get_source_component(suit_context_t * ctx, size_t idx);

/**
 * @}
 */

#endif /* SUIT_H */

