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

#define USAGE fprintf(stderr,                                                           \
        "Copyright (c) 2020, RISE Research Institutes of Sweden\n"                      \
        "All rights reserved.\n\n"                                                      \
        "Usage: %s [-hknp] > [output file] < [input file]\n"                            \
        "-h displays this text\n"                                                       \
        "-k [key file] (required)\n"                                                    \
        "-n [sequence number] (defaults to 0)\n"                                        \
        "-p parses a manifest from stdin and decodes it\n"                              \
        "\nExamples:\n"                                                                 \
        "%s -k keys/priv.pem -s 0 > manifest.bin < firmware.bin\n"                      \
        "%s -k keys/pub.pem -p < manifest.bin\n"                                        \
, argv[0], argv[0], argv[0]);

/* default values */
#define SUIT_CLASS_ID   "01234567890abdef"
#define SUIT_VENDOR_ID  "01234567890abdef"
#define SUIT_REMOTE_URI "coaps://[::1]:5683"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mbedtls/md.h>
#include "suit.h"

void read_stdin(uint8_t * wptr, uint32_t * bytes);
void hash_firmware(const uint8_t * buffer, const uint32_t len_buffer, suit_component_t * component); 
void parse_manifest(const uint8_t * buffer, const size_t len_buffer, const char * pem);
void encode_manifest(suit_context_t * ctx, uint8_t ** buffer, size_t * len_buffer, const char * pem);
void xxd(const uint8_t * data, size_t len, int w);

int main (int argc, char *argv[])
{
    char * k = NULL;  /* PEM key file */
    char * n = NULL;  /* SUIT sequence number */
    bool   p = false; /* parse_manifest manifest from stdin */
    
    int opt; /* parse command line arguments */
    while ((opt = getopt (argc, argv, "hk:n:p")) != -1) {
        switch (opt) {
        case 'h': USAGE; exit(EXIT_FAILURE);
        case 'k': k = optarg; break;
        case 'n': n = optarg; break;
        case 'p': p = true;   break;
        }
    }
    
    /* buffer for PEM-formatted key */
    char * pem = (char *) malloc(2048);

    if (k != NULL) { /* read key from PEM file */

        FILE * fptr = fopen(k, "r"); char sym;
        if (fptr != NULL) while ((sym = getc(fptr)) != EOF) strcat(pem, &sym);
        fclose(fptr);
          
    } else { /* no key file specified */

        free(pem); USAGE; exit(EXIT_FAILURE);

    }

    /* buffer for I/O */
    uint32_t bytes = 0;
    uint8_t * ibuff = (uint8_t *) malloc(2048);
    read_stdin(ibuff, &bytes);

    //printf("Image size\t%d [B]\n", bytes);
    
    if (p) { /* parse_manifest existing manifest from stdin */

        /* do something... */

    } else { /* write new manifest */

        suit_context_t ctx;
        ctx.version = 1;
        ctx.component_count = 1;

        if (n == NULL) ctx.sequence_number = 0;
        else ctx.sequence_number = (uint32_t) strtol(n, NULL, 0);

        ctx.components[0].uri = SUIT_REMOTE_URI;
        ctx.components[0].len_uri = strlen(SUIT_REMOTE_URI);
        ctx.components[0].class_id = SUIT_CLASS_ID;
        ctx.components[0].len_class_id = strlen(SUIT_CLASS_ID);
        ctx.components[0].vendor_id = SUIT_VENDOR_ID;
        ctx.components[0].len_vendor_id = strlen(SUIT_VENDOR_ID); 

        hash_firmware(ibuff, bytes, &ctx.components[0]);
        //xxd(ctx.components[0].digest, ctx.components[0].len_digest, 32); 

    }

    free(pem);
    free(ibuff);
    return 0;
}

void read_stdin(uint8_t * wptr, uint32_t * bytes)
{
    while (read(STDIN_FILENO, wptr, 1) > 0) { 
        (*bytes)++; 
        wptr++; 
    }
}

void hash_firmware(const uint8_t * buffer, const uint32_t len_buffer, suit_component_t * component)
{
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    const mbedtls_md_info_t * md_info = mbedtls_md_info_from_type(md_type);
    component->digest = malloc(mbedtls_md_get_size(md_info));
    mbedtls_md(md_info, buffer, len_buffer, component->digest);
    component->len_digest = mbedtls_md_get_size(md_info); 
    component->digest_alg = suit_digest_alg_sha256;
    component->size = len_buffer;
}

void parse_manifest(const uint8_t * buffer, size_t len_buffer, const char * pem)
{
    size_t bytes = 0;
    size_t len_manifest = 2048;
    uint8_t * manifest = malloc(len_manifest);

    int err;
    err = suit_unwrap(pem, buffer, len_buffer, (const uint8_t **) &manifest, &bytes);
    if (err) fprintf(stderr, "suit_unwrap returned: %d\n", err);
    
    suit_context_t ctx;
    err = suit_parse(&ctx, manifest, bytes);
    if (err) fprintf(stderr, "suit_parse_init returned %d\n", err);
}

void encode_manifest(suit_context_t * ctx, uint8_t ** buffer, size_t * len_buffer, const char * pem)
{
    
}

void xxd(const uint8_t * data, size_t len, int w)
{
    size_t i, j;
    for (i = 0; i < len; i += w) {
        for (j = 0; j < w; j++) {
            if (i + j == len) break;
            else printf("%02x", *(data + i + j));
        }
        printf("\n");
    }
}
