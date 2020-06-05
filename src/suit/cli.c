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
        "Copyright (c) 2020, RISE AB\n"                                                 \
        "All rights reserved.\n\n"                                                      \
        "Usage: %s [-cknruv] [output file]\n"                                           \
        "-c [class ID]                   (optional)\n"                                  \
        "-k [PEM file]                   (required)\n"                                  \
        "-n [version number]             (optional)\n"                                  \
        "-u [remote URI]                 (optional)\n"                                  \
        "-v [vendor ID]                  (optional)\n"                                  \
        "-p requires no argument. An existing manifest is parsed from stdin.\n"         \
        "\nExamples:\n"                                                                 \
        "cat firmware.bin | %s -k keys/priv.pem -n 2 -u coap://[::1] manifest.bin\n"    \
        "cat manfest.bin | %s -p -k keys/pub.pem -\n"                                   \
, argv[0], argv[0], argv[0]);

/* default values */
#define DEFC "01234567890abdef" /* SUIT class ID */
#define DEFV "01234567890abdef" /* SUIT vendor ID */
#define DEFN "0"                /* SUIT version number */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "suit.h"

static void parse(const uint8_t * buffer, const size_t len_buffer, const char * pem);
static void encode(suit_context_t * ctx, uint8_t ** buffer, size_t * len_buffer, const char * pem);

int main (int argc, char *argv[])
{
    char * k = NULL;  /* PEM key file */
    char * u = NULL;  /* SUIT uri */
    char * n = NULL;  /* SUIT version number */
    char * c = NULL;  /* SUIT class ID */
    char * v = NULL;  /* SUIT vendor ID */
    bool   p = false; /* parse manifest from stdin */
    
    int opt; /* parse command line arguments */
    while ((opt = getopt (argc, argv, "k:u:n:c:v:p")) != -1) {
        switch (opt) {
        case 'k': k = optarg; break;
        case 'u': u = optarg; break;
        case 'n': n = optarg; break;
        case 'c': c = optarg; break;
        case 'v': v = optarg; break;
        case 'p': p = true;   break;
        default: USAGE; exit(EXIT_FAILURE);
        }
    }
    
    /* buffer for PEM-formatted key */
    size_t len_pem = 2048;
    char * pem = (char *) malloc(len_pem);

    if (k != NULL) { /* read key from PEM file */

        FILE * fptr = fopen(k, "r"); char sym;
        if (fptr != NULL) while ((sym = getc(fptr)) != EOF) strcat(pem, &sym);
        fclose(fptr);
          
    } else { /* no key file specified */
        free(pem); USAGE; exit(EXIT_FAILURE);
    }

    /* buffer for I/O */
    size_t bytes = 0;
    size_t len_buffer = 2048; 
    uint8_t * buffer = (uint8_t *) malloc(len_buffer);
    
    if (p) { /* parse existing manifest from stdin */

        uint8_t * wptr = buffer;
        while (read(STDIN_FILENO, wptr, 1) > 0) { bytes++; wptr++; }
        parse(buffer, len_buffer, pem);

    } else { /* write new manifest */

        suit_context_t ctx;


        if (n == NULL) { printf("Using default version number: %s\n", DEFN); n = DEFN; }
        if (c == NULL) { printf("Using default class ID: %s\n",       DEFC); c = DEFC; }
        if (v == NULL) { printf("Using default vendor ID: %s\n",      DEFV); v = DEFV; }

    }

    /* output file name is the last non-option argument specified */
    char * filename; 
    for (int idx = optind; idx < argc; idx++) filename = argv[idx];

    free(pem);
    free(buffer);
    return 0;
}

static void parse(const uint8_t * buffer, const size_t len_buffer, const char * pem)
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

static void encode(suit_context_t * ctx, uint8_t ** buffer, size_t * len_buffer, const char * pem)
{
    
}
