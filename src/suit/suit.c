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

#include "suit.h"

/**
 * All strings in the SUIT manifest are copied by reference to their memory
 * locations in the manifest itself. The caller must not deallocate the memory
 * containing the original manifest until processing is complete. This parser
 * does not support soft-failure; any error will result in total rejection.
 **/

/* default size of stack-allocated buffers for serialization */
#define SUIT_STACK_BUFFER 256

#define RETURN_ERROR(x) err = x; if (err) return err;

#define CBOR_ENTER_ARR(nc1, nc2) \
    if (nanocbor_enter_array(&nc1, &nc2) < 0) return SUIT_ERROR_CBOR;

#define CBOR_ENTER_MAP(nc1, nc2) \
    if (nanocbor_enter_map(&nc1, &nc2) < 0) return SUIT_ERROR_CBOR;

#define CBOR_GET_INT(nc, val) \
    if (nanocbor_get_uint32(&nc, &val) < 0) return SUIT_ERROR_CBOR;

#define CBOR_GET_BSTR(nc, val, len_val) \
    if (nanocbor_get_bstr(&nc, (const uint8_t **) &val, &len_val) < 0) \
        return SUIT_ERROR_CBOR;

#define CBOR_GET_TSTR(nc, val, len_val) \
    if (nanocbor_get_tstr(&nc, (const uint8_t **) &val, &len_val) < 0) \
        return SUIT_ERROR_CBOR;

#define CBOR_INIT_ARR(nc, buf, len_buf, items) \
    nanocbor_encoder_init(&nc, buf, len_buf); \
    nanocbor_fmt_array(&nc, items);

#define CBOR_INIT_MAP(nc, buf, len_buf, pairs) \
    nanocbor_encoder_init(&nc, buf, len_buf); \
    nanocbor_fmt_map(&nc, pairs);

/*******************************************************************************
 * @section Manifest parser (private)
 ******************************************************************************/

int _suit_parse_image_digest(suit_component_t * comp,
        const uint8_t * md, size_t len_md)
{
    nanocbor_value_t top, arr;
    nanocbor_decoder_init(&top, md, len_md);
    CBOR_ENTER_ARR(top, arr);

    if (nanocbor_get_uint32(&arr, (uint32_t *) &comp->digest_alg) < 0)
        return SUIT_ERROR_CBOR;
    CBOR_GET_BSTR(arr, comp->digest, comp->len_digest);

    return SUIT_ERROR_NONE;
}

int _suit_parse_parameters(suit_context_t * ctx,
        size_t idx, nanocbor_value_t * map, bool override)
{
    suit_component_t * comp = &ctx->components[idx];

    uint32_t map_key; uint32_t map_val; int err;
    while (!nanocbor_at_end(map)) {
        CBOR_GET_INT(*map, map_key);
        switch (map_key) {

            /* The id and uri fields are copied by reference. */
            case suit_param_vendor_id:
                if (override || comp->vendor_id == NULL)
                    CBOR_GET_BSTR(*map, comp->vendor_id, comp->len_vendor_id);
                break;

            case suit_param_class_id:
                if (override || comp->class_id == NULL)
                    CBOR_GET_BSTR(*map, comp->class_id, comp->len_class_id);
                break;

            case suit_param_uri:
                if (override || comp->uri == NULL)
                    CBOR_GET_TSTR(*map, comp->uri, comp->len_uri);
                break;

            /* Image digests are wrapped: bstr(arr(uint, bstr(hash))). */ 
            case suit_param_image_digest:
                if (override || comp->digest == NULL) {
                    uint8_t * md; size_t len_md;
                    CBOR_GET_BSTR(*map, md, len_md);
                    RETURN_ERROR(_suit_parse_image_digest(comp, md, len_md));
                }
                break;

            /* The image size and archive information are copied by value. */
            case suit_param_image_size:
                if (override || comp->size == 0) CBOR_GET_INT(*map, comp->size);
                break;

            case suit_param_archive_info:
                if (override || comp->archive_alg == 0)
                    if (nanocbor_get_uint32(
                                map, (uint32_t *) &comp->archive_alg) < 0)
                        return SUIT_ERROR_CBOR;
                break;

            /**
             * A source is a reference from one manifest component to another.
             * This is stored as a pointer in the suit_component struct.
             **/
            case suit_param_source_comp:
                CBOR_GET_INT(*map, map_val);
                if (override || comp->source == NULL) 
                    comp->source = &ctx->components[map_val];
                break;

            /* FAIL if unsupported */
            default: return SUIT_ERROR_UNSUPPORTED;

        }
    }
    return SUIT_ERROR_NONE;
}

int _suit_parse_sequence(suit_context_t * ctx,
        uint32_t idx, const uint8_t * seq, size_t len_seq)
{
    nanocbor_value_t top, arr, subarr, map;
    nanocbor_decoder_init(&top, seq, len_seq);
    uint8_t * tmp; size_t len_tmp; bool pass;

    CBOR_ENTER_ARR(top, arr);
    uint32_t arr_key; int err;
    while (!nanocbor_at_end(&arr)) {
        CBOR_GET_INT(arr, arr_key);
        switch (arr_key) {

            /* DIRECTIVE override parameters */
            case suit_dir_override_params:
                CBOR_ENTER_MAP(arr, map);
                RETURN_ERROR(_suit_parse_parameters(ctx, idx, &map, true));
                nanocbor_skip(&arr); break;

            /* DIRECTIVE set parameters */
            case suit_dir_set_params:
                CBOR_ENTER_MAP(arr, map);
                RETURN_ERROR(_suit_parse_parameters(ctx, idx, &map, false));
                nanocbor_skip(&arr); break;

            /* DIRECTIVE run this component */
            case suit_dir_run:
                ctx->components[idx].run = true;
                nanocbor_skip(&arr); break;

            /* DIRECTIVE set component index */
            case suit_dir_set_comp_idx:
                CBOR_GET_INT(arr, idx);
                if (idx > ctx->component_count - 1)
                    return SUIT_ERROR_COMPONENTS;
                break;

            /**
             * This condition is underspecified in the latest draft. There is
             * insufficient information to create a working implementation.
             **/

            /* CONDITION check component offset */
            case suit_cond_comp_offset:
                nanocbor_skip(&arr); break;

            /**
             * This directive provides an ordered list of command sequences to
             * attempt. The first to succeed is accepted. If all fail, the
             * manifest is rejected.
             **/

            /* DIRECTIVE try each */
            case suit_dir_try_each:
                pass = false;
                CBOR_ENTER_ARR(arr, subarr);
                while (!nanocbor_at_end(&subarr)) {
                    CBOR_GET_BSTR(subarr, tmp, len_tmp);
                    if (!_suit_parse_sequence(ctx, idx, tmp, len_tmp)) {
                        pass = true; break;
                    }
                }
                if (!pass) return 1;
                nanocbor_skip(&arr); break;

            /**
             * These conditions and directives are not parsed directly. They
             * are implied by the existence of other fields in the manifest.
             *  - vendor ids should be checked, if present
             *  - class ids should be checked, if present
             *  - digests should be verified, if present
             *  - components should be fetched if a uri is present
             *  - components should be copied if a source component is declared
             */

            /* CONDITION check vendor id */
            case suit_cond_vendor_id:
                nanocbor_skip(&arr); break;

            /* CONDITION check class id */
            case suit_cond_class_id:
                nanocbor_skip(&arr); break;

            /* CONDITION check component digest */
            case suit_cond_image_match:
                nanocbor_skip(&arr); break;

            /* DIRECTIVE fetch this component */
            case suit_dir_fetch:
                nanocbor_skip(&arr); break;

            /* DIRECTIVE copy this component */
            case suit_dir_copy:
                nanocbor_skip(&arr); break;

            /* FAIL if unsupported */
            default: return SUIT_ERROR_UNSUPPORTED;

        }
    }
    return SUIT_ERROR_NONE;
}

int _suit_parse_common(suit_context_t * ctx,
        const uint8_t * comm, size_t len_comm)
{
    nanocbor_value_t top, map, arr, elem;
    nanocbor_decoder_init(&top, comm, len_comm);
    uint8_t * tmp; size_t len_tmp;

    CBOR_ENTER_MAP(top, map);
    uint32_t map_key; int err;
    while (!nanocbor_at_end(&map)) {
        CBOR_GET_INT(map, map_key);
        switch (map_key) {

            /**
             * The number of components listed in the manifest must not exceed
             * the recipient's specified limit (see I-D Section 5.4). The
             * components are referenced by index in the manifest. The component
             * ids can be discarded.
             **/
            case suit_common_comps:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                nanocbor_decoder_init(&arr, tmp, len_tmp);
                CBOR_ENTER_ARR(arr, elem);
                ctx->component_count = elem.remaining;
                if (ctx->component_count > SUIT_MAX_COMPONENTS)
                    return SUIT_ERROR_COMPONENTS;
                break;

            case suit_common_seq:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                RETURN_ERROR(_suit_parse_sequence(ctx, 0, tmp, len_tmp));
                break;

            /* CONTINUE if unsupported */
            default: nanocbor_skip(&map); break;
        }
    }
    return SUIT_ERROR_NONE;
}

/*******************************************************************************
 * @section Manifest parser (public)
 ******************************************************************************/

int suit_parse(suit_context_t * ctx, const uint8_t * man, size_t len_man)
{
    nanocbor_value_t top, map;
    nanocbor_decoder_init(&top, man, len_man);
    uint8_t * tmp; size_t len_tmp;

    /* initialize components */
    suit_component_t nil = {
        .run            = false,
        .size           = 0,
        .digest_alg     = 0,
        .archive_alg    = 0,
        .source         = NULL,
        .uri            = NULL,
        .digest         = NULL,
        .class_id       = NULL,
        .vendor_id      = NULL,
    };

    for (size_t idx = 0; idx < SUIT_MAX_COMPONENTS; idx++)
        ctx->components[idx] = nil;

    /* parse top-level map */
    CBOR_ENTER_MAP(top, map);
    uint32_t map_key; int err;
    while (!nanocbor_at_end(&map)) {
        CBOR_GET_INT(map, map_key);
        switch (map_key) {

            case suit_header_common:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                RETURN_ERROR(_suit_parse_common(ctx, tmp, len_tmp));
                break;

            case suit_header_manifest_version:
                CBOR_GET_INT(map, ctx->version);
                if (ctx->version != 1) return SUIT_ERROR_VERSION;
                break;

            case suit_header_manifest_seq_num:
                CBOR_GET_INT(map, ctx->sequence_number);
                break;

            case suit_header_payload_fetch:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                RETURN_ERROR(_suit_parse_sequence(ctx, 0, tmp, len_tmp));
                break;

            case suit_header_install:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                RETURN_ERROR(_suit_parse_sequence(ctx, 0, tmp, len_tmp));
                break;

            case suit_header_validate:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                RETURN_ERROR(_suit_parse_sequence(ctx, 0, tmp, len_tmp));
                break;

            case suit_header_load:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                RETURN_ERROR(_suit_parse_sequence(ctx, 0, tmp, len_tmp));
                break;

            case suit_header_run:
                CBOR_GET_BSTR(map, tmp, len_tmp);
                RETURN_ERROR(_suit_parse_sequence(ctx, 0, tmp, len_tmp));
                break;

            /* FAIL if unsupported */
            default: return SUIT_ERROR_UNSUPPORTED;

        }
    }
    return SUIT_ERROR_NONE;
}

bool suit_match_digest(suit_context_t * ctx, size_t idx, 
        const uint8_t * digest, size_t len_digest)
{
    if (ctx->components[idx].digest_alg != 0 
            && ctx->components[idx].digest != NULL)
        if (len_digest == ctx->components[idx].len_digest)
            if (!memcmp(digest, ctx->components[idx].digest, len_digest))
                return true;
    return false;
}

bool suit_match_class_id(suit_context_t * ctx, size_t idx,
        const uint8_t * class_id, size_t len_class_id)
{
    if (ctx->components[idx].class_id != NULL)
        if (len_class_id == ctx->components[idx].len_class_id)
            if (!memcmp(class_id, ctx->components[idx].class_id, len_class_id))
                return true;
    return false;
}

bool suit_match_vendor_id(suit_context_t * ctx, size_t idx,
        const uint8_t * vendor_id, size_t len_vendor_id)
{
    if (ctx->components[idx].vendor_id != NULL)
        if (len_vendor_id == ctx->components[idx].len_vendor_id)
            if (!memcmp(vendor_id, ctx->components[idx].vendor_id,
                        len_vendor_id))
                return true;
    return false;
}

/*******************************************************************************
 * @section Manifest encoder (private)
 ******************************************************************************/

int _suit_encode_oneoff(uint32_t val, uint8_t * wptr, size_t * bytes)
{
    nanocbor_encoder_t nc;
    CBOR_INIT_ARR(nc, wptr, *bytes, 1);

        nanocbor_fmt_uint(&nc, val);
        nanocbor_fmt_null(&nc);

    *bytes = nanocbor_encoded_len(&nc);
    return SUIT_ERROR_NONE;
}

int _suit_encode_install(suit_component_t * comp,
        uint8_t * wptr, size_t * bytes)
{
    nanocbor_encoder_t nc;
    CBOR_INIT_ARR(nc, wptr, *bytes, 6);

        /* remote uri */
        nanocbor_fmt_uint(&nc, suit_dir_set_params);
        nanocbor_fmt_map(&nc, 1);

            nanocbor_fmt_uint(&nc, suit_param_uri);
            nanocbor_put_tstr(&nc, (char *) comp->uri);

        /* directives and conditions */
        nanocbor_fmt_uint(&nc, suit_dir_fetch); nanocbor_fmt_null(&nc);
        nanocbor_fmt_uint(&nc, suit_cond_image_match); nanocbor_fmt_null(&nc);

    *bytes = nanocbor_encoded_len(&nc);
    return SUIT_ERROR_NONE;
}

int _suit_encode_image_digest(suit_component_t * comp,
        uint8_t * wptr, size_t * bytes)
{
    nanocbor_encoder_t nc;
    CBOR_INIT_ARR(nc, wptr, *bytes, 2);

        nanocbor_fmt_uint(&nc, (uint32_t) comp->digest_alg);
        nanocbor_put_bstr(&nc, comp->digest, comp->len_digest);

    *bytes = nanocbor_encoded_len(&nc);
    return SUIT_ERROR_NONE;
}

int _suit_encode_common_sequence(suit_component_t * comp,
        uint8_t * wptr, size_t * bytes)
{
    nanocbor_encoder_t nc;
    CBOR_INIT_ARR(nc, wptr, *bytes, 6);

        /* parameter overrides */
        nanocbor_fmt_uint(&nc, suit_dir_override_params);
        nanocbor_fmt_map(&nc, 4);

            /* vendor id */
            nanocbor_fmt_uint(&nc, suit_param_vendor_id);
            nanocbor_put_bstr(&nc, comp->vendor_id, comp->len_vendor_id);

            /* class id */
            nanocbor_fmt_uint(&nc, suit_param_class_id);
            nanocbor_put_bstr(&nc, comp->class_id, comp->len_class_id);

            /* image digest */
            nanocbor_fmt_uint(&nc, suit_param_image_digest);
            size_t len_digest = SUIT_STACK_BUFFER;
            uint8_t digest[SUIT_STACK_BUFFER];
            _suit_encode_image_digest(comp, digest, &len_digest);
            nanocbor_put_bstr(&nc, digest, len_digest);

            /* image size */
            nanocbor_fmt_uint(&nc, suit_param_image_size);
            nanocbor_fmt_uint(&nc, comp->size);

        /* directives and conditions */
        nanocbor_fmt_uint(&nc, suit_cond_vendor_id); nanocbor_fmt_null(&nc);
        nanocbor_fmt_uint(&nc, suit_cond_class_id); nanocbor_fmt_null(&nc);

    *bytes = nanocbor_encoded_len(&nc);
    return SUIT_ERROR_NONE;
}

int _suit_encode_common_components(suit_context_t * ctx,
        uint8_t * wptr, size_t * bytes)
{
    nanocbor_encoder_t nc;
    CBOR_INIT_ARR(nc, wptr, *bytes, ctx->component_count);

    /* Components are declared in an array of single-element arrays... */
    uint8_t name = 0;
    for (int i = 0; i < ctx->component_count; i++) {
        nanocbor_fmt_array(&nc, 1);
        nanocbor_put_bstr(&nc, &name, 1);
        name++;
    }

    *bytes = nanocbor_encoded_len(&nc);
    return SUIT_ERROR_NONE;
}

int _suit_encode_common(suit_context_t * ctx, uint8_t * wptr, size_t * bytes)
{
    nanocbor_encoder_t nc;
    CBOR_INIT_MAP(nc, wptr, *bytes, 2);

        /* components */
        nanocbor_fmt_uint(&nc, suit_common_comps);
        size_t len_comps = SUIT_STACK_BUFFER; uint8_t comps[SUIT_STACK_BUFFER];
        _suit_encode_common_components(ctx, comps, &len_comps);
        nanocbor_put_bstr(&nc, comps, len_comps);

        /* common sequence */
        nanocbor_fmt_uint(&nc, suit_common_seq);
        size_t len_seq = SUIT_STACK_BUFFER; uint8_t seq[SUIT_STACK_BUFFER];
        _suit_encode_common_sequence(&ctx->components[0], seq, &len_seq);
        nanocbor_put_bstr(&nc, seq, len_seq);

    *bytes = nanocbor_encoded_len(&nc);
    return SUIT_ERROR_NONE;
}

/*******************************************************************************
 * @section Manifest encoder (public)
 ******************************************************************************/

int suit_encode(suit_context_t * ctx, uint8_t * man, size_t * len_man)
{
    /**
     * Some parameters are hard-coded here to support a download/install/secure
     * boot scenario. The top-level map contains all fields supported by 
     * suit_parse() except payload fetch. The remote uri should, instead, be
     * encoded in the install sequence (according to Example 2 in the I-D).
     **/

    uint8_t buf[SUIT_STACK_BUFFER];
    size_t len_buf;

    /* encode top-level map tag*/
    nanocbor_encoder_t nc;
    CBOR_INIT_MAP(nc, man, *len_man, 6);

        /* manifest version */
        nanocbor_fmt_uint(&nc, suit_header_manifest_version);
        nanocbor_fmt_uint(&nc, ctx->version);

        /* manifest sequence number */
        nanocbor_fmt_uint(&nc, suit_header_manifest_seq_num);
        nanocbor_fmt_uint(&nc, ctx->sequence_number);

        /* common */
        nanocbor_fmt_uint(&nc, suit_header_common);
        len_buf = SUIT_STACK_BUFFER;
        _suit_encode_common(ctx, buf, &len_buf);
        nanocbor_put_bstr(&nc, buf, len_buf);

        /* install */ 
        nanocbor_fmt_uint(&nc, suit_header_install);
        len_buf = SUIT_STACK_BUFFER;
        _suit_encode_install(&ctx->components[0], buf, &len_buf);
        nanocbor_put_bstr(&nc, buf, len_buf);
    
        /* validate */
        nanocbor_fmt_uint(&nc, suit_header_validate);
        len_buf = SUIT_STACK_BUFFER;
        _suit_encode_oneoff((uint32_t) suit_cond_image_match, buf, &len_buf);
        nanocbor_put_bstr(&nc, buf, len_buf);

        /* run */
        nanocbor_fmt_uint(&nc, suit_header_run);
        len_buf = SUIT_STACK_BUFFER;
        _suit_encode_oneoff((uint32_t) suit_dir_run, buf, &len_buf);
        nanocbor_put_bstr(&nc, buf, len_buf);

    *len_man = nanocbor_encoded_len(&nc);
    return SUIT_ERROR_NONE;
}

/*******************************************************************************
 * @section Authentication wrapper (private)
 ******************************************************************************/

int _suit_unwrap(
        cose_sign_context_t * ctx,
        const uint8_t * env, const size_t len_env,
        const uint8_t ** man, size_t * len_man)
{
    cose_hash_context_t ctx_hash;
    ctx_hash.type = COSE_SHA256_TYPE;

    /* bytestrings to be extracted */
    uint8_t * pld, * hash, * auth_arr, * auth, * man_start;
    size_t len_pld, len_hash, len_auth_arr, len_auth;

    /* parse top-level map */
    nanocbor_value_t top, map, tmp0, tmp1;
    nanocbor_decoder_init(&top, env, len_env);
    CBOR_ENTER_MAP(top, map);

    uint32_t map_key; int err;
    while (!nanocbor_at_end(&map)) {
        CBOR_GET_INT(map, map_key);
        switch (map_key) {

            case suit_envelope_authentication_wrapper:

                /* unwrap */
                CBOR_GET_BSTR(map, auth_arr, len_auth_arr);
                nanocbor_decoder_init(&tmp0, auth_arr, len_auth_arr);
                CBOR_ENTER_ARR(tmp0, tmp1);
                CBOR_GET_BSTR(tmp1, auth, len_auth);

                /* get payload */
                err = cose_sign1_read(ctx, auth, len_auth, 
                        (const uint8_t **) &pld, &len_pld);
                if (err) return err;

                /* extract manifest hash */
                nanocbor_decoder_init(&tmp0, pld, len_pld);
                CBOR_ENTER_ARR(tmp0, tmp1);
                uint32_t digest_alg; CBOR_GET_INT(tmp1, digest_alg);
                if (digest_alg != suit_digest_alg_sha256) 
                    return SUIT_ERROR_UNSUPPORTED;
                CBOR_GET_BSTR(tmp1, hash, len_hash);
                break;

            case suit_envelope_manifest:

                /* get the start address of the bstr-wrapped manifest */
                man_start = (uint8_t *) map.cur;

                /* extract manifest */
                CBOR_GET_BSTR(map, *man, *len_man);

                /* hash the bstr-wrapped manifest */
                cose_hash(&ctx_hash, man_start, (*man + *len_man) - man_start);
                break;
        }
    }

    /* extracted and computed hashes must match */
    if (ctx_hash.len != len_hash) return SUIT_ERROR_HASH;
    if (memcmp(hash, ctx_hash.hash, ctx_hash.len)) return SUIT_ERROR_HASH;

    cose_sign_free(ctx);
    return SUIT_ERROR_NONE;
}

int _suit_wrap(cose_sign_context_t * ctx,
        const uint8_t * man, const size_t len_man,
        uint8_t * env, size_t * len_env)
{
    /* wrap encoded manifest in a bstr */
    uint8_t man_bstr[SUIT_STACK_BUFFER];
    nanocbor_encoder_t nc;
    nanocbor_encoder_init(&nc, man_bstr, SUIT_STACK_BUFFER);
    nanocbor_put_bstr(&nc, man, len_man);
    size_t len_man_bstr = nanocbor_encoded_len(&nc);

    /* hash the bstr-wrapped manifest */
    cose_hash_context_t ctx_hash;
    ctx_hash.type = COSE_SHA256_TYPE;
    cose_hash(&ctx_hash, man_bstr, len_man_bstr);

    /* generate authentication wrapper payload */
    uint8_t pld[SUIT_STACK_BUFFER];
    CBOR_INIT_ARR(nc, pld, SUIT_STACK_BUFFER, 2);
    nanocbor_fmt_uint(&nc, suit_digest_alg_sha256);
    nanocbor_put_bstr(&nc, ctx_hash.hash, ctx_hash.len);
    size_t len_pld = nanocbor_encoded_len(&nc);

    /* generate the authentication wrapper */
    uint8_t auth[SUIT_STACK_BUFFER];
    size_t len_auth = SUIT_STACK_BUFFER;
    int err = cose_sign1_write(ctx, pld, len_pld, auth, &len_auth);
    if (err) return err;

    /* wrap the encoded authentication wrapper in a bstr AND an array... */
    uint8_t auth_arr[SUIT_STACK_BUFFER];
    CBOR_INIT_ARR(nc, auth_arr, SUIT_STACK_BUFFER, 1);
    nanocbor_put_bstr(&nc, auth, len_auth);
    size_t len_auth_arr = nanocbor_encoded_len(&nc);

    /* generate the envelope */
    CBOR_INIT_MAP(nc, env, *len_env, 2);
    nanocbor_fmt_uint(&nc, suit_envelope_authentication_wrapper);
    nanocbor_put_bstr(&nc, auth_arr, len_auth_arr);
    nanocbor_fmt_uint(&nc, suit_envelope_manifest);
    nanocbor_put_bstr(&nc, man, len_man);

    /* return envelope length */
    *len_env = nanocbor_encoded_len(&nc);

    cose_sign_free(ctx);
    return SUIT_ERROR_NONE;
}

/*******************************************************************************
 * @section Authentication wrapper (public)
 ******************************************************************************/

#ifdef COSE_BACKEND_NRF
int suit_raw_unwrap(
        const uint8_t * key, const size_t len_key,
        const uint8_t * env, const size_t len_env,
        const uint8_t ** man, size_t * len_man) 
{
    cose_sign_context_t ctx;
    ctx.key.curve = cose_curve_p256;
    ctx.key.alg = cose_alg_ecdsa_sha_256;
    
    int err = cose_sign_raw_init(&ctx, cose_mode_r, key, len_key);
    if (err) return err;

    return _suit_unwrap(&ctx, env, len_env, man, len_man);
}
#else
int suit_pem_unwrap(const char * pem, 
        const uint8_t * env, const size_t len_env,
        const uint8_t ** man, size_t * len_man)
{
    cose_sign_context_t ctx;

    int err = cose_sign_pem_init(&ctx, cose_mode_r, pem);
    if (err) return err;

    return _suit_unwrap(&ctx, env, len_env, man, len_man);
}

int suit_pem_wrap(const char * pem,
        const uint8_t * man, const size_t len_man,
        uint8_t * env, size_t * len_env)
{
    cose_sign_context_t ctx;

    int err = cose_sign_pem_init(&ctx, cose_mode_w, pem);
    if (err) return err;

    return _suit_wrap(&ctx, man, len_man, env, len_env); 
}
#endif
