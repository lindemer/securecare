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

#define USAGE fprintf(stderr,                                                               \
"Copyright (c) 2020, RISE Research Institutes of Sweden\n"                                  \
"All rights reserved.\n"                                                                    \
"\nUsage: %s [-hiknuv] > [output file]\n"                                                   \
"\t-h displays this text\n"                                                                 \
"\t-k [pem file]\n"                                                                         \
"\t-n [sequence number]\n"                                                                  \
"\t-u [remote firmware URI]\n"                                                              \
"\t-v parsea manifest from stdin and verifies it\n"                                         \
"\nExamples:\n"                                                                        	    \
"%s -k key/priv.pem -n 0 -u coaps://[::1]/firmware.hex -i firmware.hex > manifest.cbor\n"   \
"%s -k key/pub.pem -v < manifest.cbor\n"                                                    \
, argv[0], argv[0], argv[0]);

#define MAX_MANIFEST_SIZE 2048
#define MAX_PEM_SIZE      2048

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mbedtls/md.h>
#include "suit.h"

void read_stdin(uint8_t * wptr, uint32_t * bytes);
void hash_firmware(const uint8_t * buffer, const uint32_t len_buffer, 
        suit_component_t * component); 
void print_bstr(const uint8_t * buffer, const uint32_t len_buffer);
void xxd(const uint8_t * data, size_t len, int w);

static uint8_t class_id[] =  { 0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
                               0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45 };
static uint8_t vendor_id[] = { 0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
                               0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe };

int main(int argc, char *argv[])
{
    char * i = NULL;  /* firmware file */ 
    char * k = NULL;  /* PEM key file */
    char * n = NULL;  /* manifest sequence number */
    char * u = NULL;  /* remote firmware URI */
    bool   v = false; /* parse manifest from stdin */
    
    int opt; /* parse command line arguments */
    while ((opt = getopt (argc, argv, "hi:k:n:u:v")) != -1) {
        switch (opt) {
        case 'h': goto fail;
        case 'i': i = optarg; break;
        case 'k': k = optarg; break;
        case 'n': n = optarg; break;
        case 'u': u = optarg; break;
        case 'v': v = true;   break;
        }
    }
    
    /* buffer for PEM-formatted key */
    char * pem = (char *)malloc(MAX_PEM_SIZE);

    if (k != NULL) { /* read key from PEM file */

        FILE * fptr = fopen(k, "r"); 
        if (fptr == NULL) goto fail;
        
        char * wptr = pem;
        while (!feof(fptr)) *(wptr++) = fgetc(fptr);
        fclose(fptr);

    } else goto fail;

    if (v) { /* parse and decode existing manifest */

        uint32_t ibytes = 0;
        uint8_t * buffer = (uint8_t *)malloc(MAX_MANIFEST_SIZE);
        read_stdin(buffer, &ibytes);

        uint8_t * manifest;
	size_t len_manifest;

        if (suit_pem_unwrap(pem, buffer, MAX_MANIFEST_SIZE, 
                    (const uint8_t **) &manifest, &len_manifest)) {
            fprintf(stderr, "Signature verification failed.\n");
            exit(EXIT_FAILURE);
        }
    
        suit_context_t ctx;
        if (suit_parse(&ctx, manifest, len_manifest)) {
            fprintf(stderr, "Parser error.\n");
            exit(EXIT_FAILURE);
        }

        printf("Signature OK!\n\n");
        printf("SUIT version\t\t%d\n", ctx.version);
        printf("Component count\t\t%d\n", ctx.component_count);
        printf("Sequence number\t\t%d\n", ctx.sequence_number);

        printf("\nComponent details:\n");
        for (int i = 0; i < ctx.component_count; i++) {

            if (ctx.components[i].uri != NULL) {
                printf("(%d) Remote URI\t\t", i); 
                print_bstr(ctx.components[i].uri, ctx.components[i].len_uri);
            }

            printf("(%d) Class ID\t\t", i); 
            xxd(ctx.components[i].class_id, 
                ctx.components[i].len_class_id, 32);

            printf("(%d) Vendor ID\t\t", i); 
            xxd(ctx.components[i].vendor_id, 
                ctx.components[i].len_vendor_id, 32);

            printf("(%d) Image digest\t", i); 
            xxd(ctx.components[i].digest,
                ctx.components[i].len_digest, 32);

            printf("(%d) Image size\t\t%d [B]\n", i, ctx.components[i].size);
           
            free(buffer);
        }

    } else { /* write new manifest */
    
        uint8_t * buffer;
        size_t ibytes;

        if (i != NULL) {

            FILE * fptr = fopen(i, "r");
            if (fptr == NULL) goto fail;

            /* get file size */
            fseek(fptr, 0L, SEEK_END);
            ibytes = ftell(fptr);
            rewind(fptr);
        
            buffer = (uint8_t *)malloc(ibytes);
            char * wptr = buffer;
            while (!feof(fptr)) *(wptr++) = fgetc(fptr);

            fclose(fptr);

        } else goto fail;

        suit_context_t ctx;
        ctx.version = 1;
        ctx.component_count = 1;

        if (n == NULL) ctx.sequence_number = 0;
        else ctx.sequence_number = (uint32_t) strtol(n, NULL, 0);

        if (u == NULL) {
            goto fail;
        } else {
            ctx.components[0].uri = u;
            ctx.components[0].len_uri = strlen(u);
        }

        ctx.components[0].class_id = class_id;
        ctx.components[0].len_class_id = 16;
        ctx.components[0].vendor_id = vendor_id;
        ctx.components[0].len_vendor_id = 16; 
        ctx.components[0].archive_alg = 0;
        ctx.components[0].source = NULL;

        hash_firmware(buffer, ibytes, &ctx.components[0]);
        
        size_t len_manifest = MAX_MANIFEST_SIZE;
        uint8_t * manifest = (uint8_t *)malloc(MAX_MANIFEST_SIZE); 

        /* encode the manifest */
        suit_encode(&ctx, manifest, &len_manifest);

        /* sign the manifest */
        size_t len_envelope = MAX_MANIFEST_SIZE;
        uint8_t * envelope = (uint8_t *)malloc(MAX_MANIFEST_SIZE);

        if (suit_pem_wrap(pem, manifest, len_manifest, envelope, &len_envelope)) {
            fprintf(stderr, "Failed to encode manifest.\n");
            exit(EXIT_FAILURE);
        }

        /* write to stdout */
        fwrite(envelope, sizeof(uint8_t), len_envelope, stdout);
        free(envelope);
        free(buffer);
    }

    free(pem);
    return 0;

fail:
    USAGE; exit(EXIT_FAILURE);

}

void read_stdin(uint8_t * wptr, uint32_t * bytes)
{
    while (read(STDIN_FILENO, wptr, 1) > 0) { 
        (*bytes)++; 
        wptr++; 
    }
}

void hash_firmware(const uint8_t * buffer, const uint32_t len_buffer,
        suit_component_t * component)
{
    const mbedtls_md_info_t * md_info = 
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    component->digest = malloc(mbedtls_md_get_size(md_info));
    mbedtls_md(md_info, buffer, len_buffer, component->digest);
    component->len_digest = mbedtls_md_get_size(md_info); 
    component->digest_alg = suit_digest_alg_sha256;
    component->size = len_buffer;
}

void print_bstr(const uint8_t * buffer, const uint32_t len_buffer)
{
   for (int i = 0; i < len_buffer; i++) {
        printf("%c", buffer[i]);
   }
   printf("\n");
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
