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

#define USAGE fprintf(stderr, "Usage: %s [-abc] [file...]\n", argv[0]);

#define DEFAULT_N "0"
#define DEFAULT_C "01234567890abdef"
#define DEFAULT_V "01234567890abdef"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "suit.h"

int main (int argc, char *argv[])
{
    char * u = NULL; /* SUIT uri */
    char * n = NULL; /* SUIT version number */
    char * c = NULL; /* SUIT class ID */
    char * v = NULL; /* SUIT vendor ID */
    char * k = NULL; /* PEM key file */
    char * i = NULL; /* [input] image file */
    char * m = NULL; /* [input] manifest file */
    char * o = NULL; /* [output] manifest file */
    
    int opt; /* parse command line arguments */
    while ((opt = getopt (argc, argv, "u:n:c:v:k:i:m:o:")) != -1) {
        switch (opt) {
        case 'u': u = optarg; break;
        case 'n': n = optarg; break;
        case 'c': c = optarg; break;
        case 'v': v = optarg; break;
        case 'k': k = optarg; break;
        case 'i': i = optarg; break;
        case 'm': m = optarg; break;
        case 'o': o = optarg; break;
        default: USAGE; exit(EXIT_FAILURE);
        }
    }

    /* check argument consistency */
    if (k == NULL) { USAGE; exit(EXIT_FAILURE); }

    if (m == NULL) {
        if (i == NULL)      { USAGE; exit(EXIT_FAILURE); }
        else if (o != NULL) { USAGE; exit(EXIT_FAILURE); }
    } else if (i != NULL)   { USAGE; exit(EXIT_FAILURE); }

    if (n == NULL) { printf("Using default version number: %s\n", DEFAULT_N); n = DEFAULT_N; }
    if (c == NULL) { printf("Using default class ID: %s\n",       DEFAULT_C); c = DEFAULT_C; }
    if (v == NULL) { printf("Using default vendor ID: %s\n",      DEFAULT_V); v = DEFAULT_V; }

    for (int idx = optind; idx < argc; idx++)
        printf ("Non-option argument %s\n", argv[idx]);

    return 0;
}
