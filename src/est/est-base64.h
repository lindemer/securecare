/*
 * Copyright (c) 2015, SICS.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */
/**
 * \file
 *    BASE64 encode and decode functions
 * \author
 *    Tomas Thor Helgason <helgas@kth.se>
 *
 * Based on the libb64 project that has been placed in the public domain.
 * For details, see http://libb64.sourceforge.net/
 */

#ifndef EST_BASE64_H
#define EST_BASE64_H

#include "stdint.h"

#if (EST_DEBUG) | EST_DEBUG_BASE64
#define BASE64_DBG(...) EST_DEBUG_PRINT(__VA_ARGS__)
#else
#define BASE64_DBG(...)
#endif

typedef enum {
  step_A, step_B, step_C
} base64_encodestep;

typedef enum {
  step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct {
  base64_encodestep step;
  char result;
} base64_encodestate;

typedef struct {
  base64_decodestep step;
  char plainchar;
} base64_decodestate;

/** This function needs to be called to initialize the internal encoder state.
 * Does not allocate any memory so no cleanup function is necessary after use.
 * \param [out] state_in        Internal state of encoder.
 */
void est_base64_init_encodestate(base64_encodestate *state_in);

/** This function needs to be called to initialize the internal decoder state.
 * Does not allocate any memory so no cleanup function is necessary after use.
 * \param [out] state_in        Internal state of decoder.
 */
void est_base64_init_decodestate(base64_decodestate *state_in);

/** Encode a chunk of data.
 * This function can be called multiple times for the same state_in.
 * \param [in] plaintext_in     Data to be base64 encoded.
 * \param [in] length_in        Length of plaintext_in in bytes.
 * \param [out] code_out        Memory of at least 2 * length_in that will
 *                              contain the base64 encoded data on output.
 * \param [in,out] state_in     Internal state of encoder.
 * \return                      Byte length of encoded data in code_out.
 */
uint16_t est_base64_encode_block(const char *plaintext_in,
                                 uint16_t length_in, char *code_out,
                                 base64_encodestate *state_in);

/** Flush remaining code bytes after all input data have been encoded.
 * Must be called when the encoding is done to create valid base64 data.
 * \param [out] code_out        Memory of at least 4 bytes that will contain
 *                              the final encoded bits.
 * \param [in,out] state_in     Internal state of encoder.
 *                              Needs base64_init_encodestate to be used again.
 * \return                      Number of final bytes written to code_out.
 */
uint16_t est_base64_encode_blockend(char *code_out, base64_encodestate *state_in);

/** Length of base64 encoded data
 * This function returns the base64 encode length for data of particular length
 * \param [in] length_in        Length of data in bytes.
 * \return                      Byte length of encoded data.
 */
uint16_t est_base64_encoded_length(uint16_t length_in);

/** Encode a chunk of data inplace.
 * This function takes in buffer with data and base64 encodes to same buffer
 * The data must be in the end of the buffer and the size of the buffer must
 * be large enough for the encoded data, use est_base64_encoded_length function
 * Encoded data is in the beginning of the buffer after the function
 * \param [in] buffer_in        Buffer that has data to be encoded at the end.
 * \param [in] length_buffer    Length of the buffer provided.
 * \param [in] length_in        Length of data to be base64 encoded in bytes.
 * \return                      Byte length of encoded data in buffer_in.
 */
uint16_t est_base64_encode_block_inplace(char *buffer_in, uint16_t length_buffer,
                                         uint16_t length_in);

/** Decode a chunk of data.
 * This function can be called multiple times for the same state_in.
 * \param [in] code_in          Data in base64 encoding.
 * \param [in] length_in        Length of code_in in bytes.
 * \param [out] plaintext_out   Memory of at least length_in bytes that will
 *                              contain the plaintext on output.
 * \param [in,out] state_in     Internal state of decoder.
 * \return                      Byte length of decoded data in plaintext_out.
 */
uint16_t est_base64_decode_block(const char *code_in, uint16_t length_in,
                                 char *plaintext_out,
                                 base64_decodestate *state_in);

/** Decode a chunk of data inplace.
 * This function takes in buffer with base64 data and decodes to same buffer
 * \param [in] buffer_in        Data in base64 encoding.
 * \param [in] length_in        Length of buffer_in in bytes.
 * \return                      Byte length of decoded data in buffer_in.
 */
uint16_t est_base64_decode_block_inplace(char *buffer_in, uint16_t length_in);

#endif /* EST_BASE64_H */
