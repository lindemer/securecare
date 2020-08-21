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
#include "est-base64.h"

#include <stdio.h> //printf-debug

/*---------------------------------------------------------------------------*/
static const char *encoding =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/*---------------------------------------------------------------------------*/
static const char decoding[] =
{ 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,
  -2, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
  29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
  47, 48, 49, 50, 51 };
/*---------------------------------------------------------------------------*/
static const char decoding_size = (char)sizeof(decoding);
/*---------------------------------------------------------------------------*/
static inline char
est_base64_encode_value(char value_in)
{
  return value_in > 63 ? '=' : encoding[(int)value_in];
}
/*---------------------------------------------------------------------------*/
static inline char
est_base64_decode_value(char value_in)
{
  value_in -= 43;
  return (value_in < 0 || value_in >= decoding_size) ?
         -1 : decoding[(int)value_in];
}
/*---------------------------------------------------------------------------*/
void
est_base64_init_encodestate(base64_encodestate *state_in)
{
  state_in->step = step_A;
  state_in->result = 0;
}
/*---------------------------------------------------------------------------*/
void
est_base64_init_decodestate(base64_decodestate *state_in)
{
  state_in->step = step_a;
  state_in->plainchar = 0;
}
/*---------------------------------------------------------------------------*/
uint16_t
est_base64_encode_block(const char *plaintext_in, uint16_t length_in,
                        char *code_out, base64_encodestate *state_in)
{
  const char *plainchar = plaintext_in;
  const char *plaintextend = plaintext_in + length_in;
  char *codechar = code_out;
  char result;
  char fragment;

  result = state_in->result;

  switch(state_in->step) {
    while(1) {
    case step_A:
      if(plainchar == plaintextend) {
        state_in->result = result;
        state_in->step = step_A;
        return codechar - code_out;
      }
      fragment = *plainchar++;
      result = (char)((fragment & 0x0fc) >> 2);
      *codechar++ = est_base64_encode_value(result);
      result = (char)((fragment & 0x003) << 4);
    case step_B:
      if(plainchar == plaintextend) {
        state_in->result = result;
        state_in->step = step_B;
        return codechar - code_out;
      }
      fragment = *plainchar++;
      result = (char)(result | ((fragment & 0x0f0) >> 4));
      *codechar++ = est_base64_encode_value(result);
      result = (char)((fragment & 0x00f) << 2);
    case step_C:
      if(plainchar == plaintextend) {
        state_in->result = result;
        state_in->step = step_C;
        return codechar - code_out;
      }
      fragment = *plainchar++;
      result = (char)(result | ((fragment & 0x0c0) >> 6));
      *codechar++ = est_base64_encode_value(result);
      result = (char)((fragment & 0x03f) >> 0);
      *codechar++ = est_base64_encode_value(result);
    }
  }
  /* control should not reach here */
  return codechar - code_out;
}
/*---------------------------------------------------------------------------*/
uint16_t
est_base64_encode_blockend(char *code_out, base64_encodestate *state_in)
{
  char *codechar = code_out;

  switch(state_in->step) {
  case step_B:
    *codechar++ = est_base64_encode_value(state_in->result);
    *codechar++ = '=';
    *codechar++ = '=';
    break;
  case step_C:
    *codechar++ = est_base64_encode_value(state_in->result);
    *codechar++ = '=';
    break;
  case step_A:
    break;
  }

  return codechar - code_out;
}
/*---------------------------------------------------------------------------*/
uint16_t
est_base64_encoded_length(uint16_t length_in)
{
  return ((length_in + ((length_in % 3) ? (3 - (length_in % 3)) : 0)) / 3) * 4;
}
/*---------------------------------------------------------------------------*/
uint16_t
est_base64_encode_block_inplace(char *buffer_in, uint16_t length_buffer,
                                uint16_t length_in)
{
  uint16_t code_size = est_base64_encoded_length(length_in);
  if(length_buffer < code_size) {
    return 0;
  }
  char *plainchar = buffer_in + (length_buffer - length_in);
  char *plaintextend = buffer_in + length_buffer;
  char *codechar = buffer_in;
  char result;
  char fragment;

  while(1) {
    /* Step A */
    if(plainchar == plaintextend) {
      return codechar - buffer_in;
    }
    fragment = *plainchar++;
    result = (char)((fragment & 0x0fc) >> 2);
    *codechar++ = est_base64_encode_value(result);
    result = (char)((fragment & 0x003) << 4);

    /* Step B */
    if(plainchar == plaintextend) {
      *codechar++ = est_base64_encode_value(result);
      *codechar++ = '=';
      *codechar++ = '=';
      return codechar - buffer_in;
    }
    fragment = *plainchar++;
    result = (char)(result | ((fragment & 0x0f0) >> 4));
    *codechar++ = est_base64_encode_value(result);
    result = (char)((fragment & 0x00f) << 2);

    /* Step C */
    if(plainchar == plaintextend) {
      *codechar++ = est_base64_encode_value(result);
      *codechar++ = '=';
      return codechar - buffer_in;
    }
    fragment = *plainchar++;
    result = (char)(result | ((fragment & 0x0c0) >> 6));
    *codechar++ = est_base64_encode_value(result);
    result = (char)((fragment & 0x03f) >> 0);
    *codechar++ = est_base64_encode_value(result);
  }
  /* control should not reach here */
  return codechar - buffer_in;
}
/*---------------------------------------------------------------------------*/
uint16_t
est_base64_decode_block(const char *code_in, uint16_t length_in,
                        char *plaintext_out, base64_decodestate *state_in)
{
  const char *codechar = code_in;
  char *plainchar = plaintext_out;
  char fragment;

  *plainchar = state_in->plainchar;

  switch(state_in->step) {
    while(1) {
    case step_a:
      do {
        if(codechar == code_in + length_in || *codechar == '=') {
          state_in->step = step_a;
          state_in->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = est_base64_decode_value(*codechar++);
      } while(fragment < 0);
      *plainchar = (char)((fragment & 0x03f) << 2);
    case step_b:
      do {
        if(codechar == code_in + length_in || *codechar == '=') {
          state_in->step = step_b;
          state_in->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = est_base64_decode_value(*codechar++);
      } while(fragment < 0);
      *plainchar = (char)(*plainchar | ((fragment & 0x030) >> 4));
      ++plainchar;
      *plainchar = (char)((fragment & 0x00f) << 4);
    case step_c:
      do {
        if(codechar == code_in + length_in || *codechar == '=') {
          state_in->step = step_c;
          state_in->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = est_base64_decode_value(*codechar++);
      } while(fragment < 0);
      *plainchar = (char)(*plainchar | ((fragment & 0x03c) >> 2));
      ++plainchar;
      *plainchar = (char)((fragment & 0x003) << 6);
    case step_d:
      do {
        if(codechar == code_in + length_in || *codechar == '=') {
          state_in->step = step_d;
          state_in->plainchar = *plainchar;
          return plainchar - plaintext_out;
        }
        fragment = est_base64_decode_value(*codechar++);
      } while(fragment < 0);
      *plainchar = (char)(*plainchar | (fragment & 0x03f));
      ++plainchar;
    }
  }
  /* control should not reach here */
  return plainchar - plaintext_out;
}
/*---------------------------------------------------------------------------*/
uint16_t
est_base64_decode_block_inplace(char *buffer_in, uint16_t length_in)
{
  const char *codechar = buffer_in;
  const char *code_end = buffer_in + length_in;
  char *plainchar = buffer_in;
  char fragment;

  while(1) {
    /* Step A */
    do {
      if(codechar == code_end || *codechar == '=') {
        return plainchar - buffer_in;
      }
      fragment = est_base64_decode_value(*codechar++);
    } while(fragment < 0);
    *plainchar = (char)((fragment & 0x03f) << 2);
    /* Step B */
    do {
      if(codechar == code_end || *codechar == '=') {
        return plainchar - buffer_in;
      }
      fragment = est_base64_decode_value(*codechar++);
    } while(fragment < 0);
    *plainchar = (char)(*plainchar | ((fragment & 0x030) >> 4));
    ++plainchar;
    *plainchar = (char)((fragment & 0x00f) << 4);
    /* Step C */
    do {
      if(codechar == code_end || *codechar == '=') {
        return plainchar - buffer_in;
      }
      fragment = est_base64_decode_value(*codechar++);
    } while(fragment < 0);
    *plainchar = (char)(*plainchar | ((fragment & 0x03c) >> 2));
    ++plainchar;
    *plainchar = (char)((fragment & 0x003) << 6);
    /* Step D */
    do {
      if(codechar == code_end || *codechar == '=') {
        return plainchar - buffer_in;
      }
      fragment = est_base64_decode_value(*codechar++);
    } while(fragment < 0);
    *plainchar = (char)(*plainchar | (fragment & 0x03f));
    ++plainchar;
  }

  /* control should not reach here */
  return plainchar - buffer_in;
}
/*---------------------------------------------------------------------------*/
