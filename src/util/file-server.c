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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef R_OK
#define R_OK 4
#endif
static char* strndup(const char* s1, size_t n)
{
    char* copy = (char*)malloc(n + 1);
    if (copy) {
        memcpy(copy, s1, n);
        copy[n] = 0;
    }
    return copy;
};
#include <io.h>
#define access _access
#define fileno _fileno
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#endif

/* Need to refresh time once per sec */
#define COAP_RESOURCE_CHECK_TIME 1

#include <coap2/coap.h>

// URI queries allowed.
static char * query_crc32 = "crc32";
static char * query_size  = "size";
static char * query_meta  = "meta";

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* temporary storage for dynamic resource representations */
static int quit = 0;

static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;

static char * fsdir = "."; /* Files in this directory are accessible with GET */
static char * cert_file = NULL; /* Combined certificate and private key in PEM */
static char * ca_file = NULL;  /* CA for cert_file - for cert checking in PEM */
static char * root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int use_pem_buf = 0; /* Map these cert/key files into memory to test PEM_BUF logic if set */
static uint8_t * cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t * ca_mem = NULL; /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t ca_mem_len = 0;
static int require_peer_cert = 1; /* By default require peer cert */
#define MAX_KEY 64 /* Maximum length of a pre-shared key in bytes. */
static uint8_t key[MAX_KEY];
static ssize_t key_length = 0;
int key_defined = 0;
static const char * hint = "CoAP";

typedef struct psk_sni_def_t {
    char* sni_match;
    coap_bin_const_t * new_key;
    coap_bin_const_t * new_hint;
} psk_sni_def_t;

typedef struct valid_psk_snis_t {
    size_t count;
    psk_sni_def_t * psk_sni_list;
} valid_psk_snis_t;

static valid_psk_snis_t valid_psk_snis = {0, NULL};

typedef struct id_def_t {
    char * hint_match;
    coap_bin_const_t * identity_match;
    coap_bin_const_t * new_key;
} id_def_t;

typedef struct valid_ids_t {
    size_t count;
    id_def_t * id_list;
} valid_ids_t;

static valid_ids_t valid_ids = {0, NULL};
typedef struct pki_sni_def_t {
    char* sni_match;
    char * new_cert;
    char * new_ca;
} pki_sni_def_t;

typedef struct valid_pki_snis_t {
    size_t count;
    pki_sni_def_t * pki_sni_list;
} valid_pki_snis_t;

static valid_pki_snis_t valid_pki_snis = {0, NULL};

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

static void handle_sigint(int signum UNUSED_PARAM) { quit = 1; }

static uint8_t * read_file_mem(const char * file, size_t * length)
{
    FILE * f;
    uint8_t * buf;
    struct stat statbuf;

    *length = 0;
    if (!file || !(f = fopen(file, "r")))
        return NULL;

    if (fstat(fileno(f), &statbuf) == -1) {
        fclose(f);
        return NULL;
    }

    buf = malloc(statbuf.st_size);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, statbuf.st_size, f) != (size_t)statbuf.st_size) {
        fclose(f);
        free(buf);
        return NULL;
    }
    *length = (size_t)statbuf.st_size;
    fclose(f);
    return buf;
}

uint32_t crc32_for_byte(uint32_t r) {
  for(int j = 0; j < 8; ++j)
    r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
  return r ^ (uint32_t)0xFF000000L;
}

void crc32(const void *data, size_t n_bytes, uint32_t* crc) {
  static uint32_t table[0x100];
  if(!*table)
    for(size_t i = 0; i < 0x100; ++i)
      table[i] = crc32_for_byte(i);
  for(size_t i = 0; i < n_bytes; ++i)
    *crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

/*******************************************************************************
 * @section Index handler
 ******************************************************************************/

#define INDEX "This is a simple CoAP(s) file server made with libcoap.\n" \
              "Copyright (c) 2020, RISE Research Institutes of Sweden AB"

static void hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) 
{
    coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_TEXT_PLAIN, 0x2ffff,
                                 strlen(INDEX),
                                 (const uint8_t *)INDEX);
}

/*******************************************************************************
 * @section GET handler(s)
 ******************************************************************************/

static void hnd_get(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query UNUSED_PARAM,
        coap_pdu_t *response)
{
    uint8_t * reply;
    size_t len_reply;

    // Check if URI path is valid.
    coap_str_const_t * uri_path = coap_resource_get_uri_path(resource);
    if (!uri_path) {
        response->code = COAP_RESPONSE_CODE(404);
        return;
    }
    
    // Parse requested file.
    size_t flen;
    char * full_path = malloc(strlen(uri_path->s) + strlen(fsdir));
    sprintf(full_path, "%s/%s", fsdir, uri_path->s);
    uint8_t * buf = read_file_mem(full_path, &flen);

    // File contents returned if no query is present.
    reply = buf;
    len_reply = flen;

    // Get requester's IP address.
    struct sockaddr_in * remote = &session->addr_info.remote.addr.sin;
    char * ip = inet_ntoa(remote->sin_addr);
    printf("/%s requested by remote %s", uri_path->s, ip);

    // Check for block option.
    coap_block_t block2 = { 0, 0, 0 };
    if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)) {
        int block_size = 16 << block2.szx;
        int total_blocks = (flen / block_size) +
                ((flen % block_size) == 0 ? 0 : 1);
	if (block2.num == (total_blocks - 1)) block_size = flen % block_size;
        printf(" - block [%d/%d], size %d ",
                     block2.num, total_blocks - 1, block_size);
    }

    // Check if a URI query is present.
    coap_opt_iterator_t oi;
    coap_opt_t * opt = coap_check_option(request, COAP_OPTION_URI_QUERY, &oi);

    if (opt != NULL) {
        coap_option_t option;
        if (coap_opt_parse(opt, (size_t) - 1, &option)) {
		
            uint32_t crc;
            crc32(buf, flen, &crc);

            // [meta] Return the size and the CRC32 of the requested resource.
	    if (!memcmp(option.value, query_meta, option.length)) {
                printf(" - resource metadata queried");
                sprintf((char *)reply, "%ld,%d", flen, crc);
                len_reply = strlen(reply);
	    }

            // [crc] Return the CRC32 of the requested resource.
	    else if (!memcmp(option.value, query_crc32, option.length)) {
                printf(" - resource CRC32 queried");
                sprintf((char *)reply, "%d", crc);
                len_reply = strlen(reply);
	    }

            // [size] Return the size of the requested resource.
            else if (!memcmp(option.value, query_size, option.length)) {
                printf(" - resource size queried");
                sprintf((char *)reply, "%ld", flen);
		len_reply = strlen(reply);
            }

        }
    }

    printf("\n");

    coap_add_data_blocked_response(resource, session, request, response, token,
            COAP_MEDIATYPE_ANY, -1, len_reply, reply);
    
    free(full_path);
    free(buf);
}

/*******************************************************************************
 * @section Resource initialization
 ******************************************************************************/

/**
 * Add all regular files in path as CoAP GET resources.
 **/
static void load_directory(char * path, coap_context_t * ctx)
{
    coap_resource_t * r;
    DIR * dir;
    struct dirent * ent;

    if ((dir = opendir(path)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG) {
                r = coap_resource_init(coap_make_str_const(ent->d_name),
                        resource_flags);
                coap_register_handler(r, COAP_REQUEST_GET, hnd_get);
                coap_resource_set_get_observable(r, 0);
                coap_add_resource(ctx, r);
                if (r != NULL) printf("Resource added: /%s\n", ent->d_name);
            }
        }
        closedir(dir);
    } else {
        perror("");
        exit(EXIT_FAILURE);
    }
}

static void init_resources(coap_context_t * ctx)
{
    coap_resource_t * r;

    r = coap_resource_init(NULL, 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
    coap_add_resource(ctx, r);

    load_directory(fsdir, ctx);
}

/*******************************************************************************
 * @section Certificate and key handling
 ******************************************************************************/

static int verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert UNUSED_PARAM,
                   size_t asn1_length UNUSED_PARAM,
                   coap_session_t *session UNUSED_PARAM,
                   unsigned depth,
                   int validated UNUSED_PARAM,
                   void *arg UNUSED_PARAM)
{
    coap_log(LOG_INFO, "CN '%s' presented by client (%s)\n",
            cn, depth ? "CA" : "Certificate");
    return 1;
}

static coap_dtls_key_t * verify_pki_sni_callback(const char *sni,
                    void *arg UNUSED_PARAM) 
{
    static coap_dtls_key_t dtls_key;

    /* Preset with the defined keys */
    memset (&dtls_key, 0, sizeof(dtls_key));
    if (!use_pem_buf) {
        dtls_key.key_type = COAP_PKI_KEY_PEM;
        dtls_key.key.pem.public_cert = cert_file;
        dtls_key.key.pem.private_key = cert_file;
        dtls_key.key.pem.ca_file = ca_file;
    }
    else {
        dtls_key.key_type = COAP_PKI_KEY_PEM_BUF;
        dtls_key.key.pem_buf.ca_cert = ca_mem;
        dtls_key.key.pem_buf.public_cert = cert_mem;
        dtls_key.key.pem_buf.private_key = cert_mem;
        dtls_key.key.pem_buf.ca_cert_len = ca_mem_len;
        dtls_key.key.pem_buf.public_cert_len = cert_mem_len;
        dtls_key.key.pem_buf.private_key_len = cert_mem_len;
    }
    if (sni[0]) {
        size_t i;
        coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
        for (i = 0; i < valid_pki_snis.count; i++) {
            /* Test for SNI to change cert + ca */
            if (strcasecmp(sni, valid_pki_snis.pki_sni_list[i].sni_match) == 0) {
                coap_log(LOG_INFO, "Switching to using cert '%s' + ca '%s'\n",
                    valid_pki_snis.pki_sni_list[i].new_cert,
                    valid_pki_snis.pki_sni_list[i].new_ca);
                dtls_key.key_type = COAP_PKI_KEY_PEM;
                dtls_key.key.pem.public_cert = valid_pki_snis.pki_sni_list[i].new_cert;
                dtls_key.key.pem.private_key = valid_pki_snis.pki_sni_list[i].new_cert;
                dtls_key.key.pem.ca_file = valid_pki_snis.pki_sni_list[i].new_ca;
                break;
            }
        }
    } else {
        coap_log(LOG_DEBUG, "SNI not requested\n");
    }
    return &dtls_key;
}

static const coap_dtls_spsk_info_t * verify_psk_sni_callback(const char *sni,
                    coap_session_t *c_session UNUSED_PARAM,
                    void *arg UNUSED_PARAM)
{
    static coap_dtls_spsk_info_t psk_info;

    /* Preset with the defined keys */
    memset (&psk_info, 0, sizeof(psk_info));
    psk_info.hint.s = (const uint8_t *)hint;
    psk_info.hint.length = hint ? strlen(hint) : 0;
    psk_info.key.s = key;
    psk_info.key.length = key_length;
    if (sni) {
        size_t i;
        coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
        for (i = 0; i < valid_psk_snis.count; i++) {
            /* Test for identity match to change key */
            if (strcasecmp(sni, valid_psk_snis.psk_sni_list[i].sni_match) == 0) {
                coap_log(LOG_INFO, "Switching to using '%.*s' hint + '%.*s' key\n",
                    (int)valid_psk_snis.psk_sni_list[i].new_hint->length,
                    valid_psk_snis.psk_sni_list[i].new_hint->s,
                    (int)valid_psk_snis.psk_sni_list[i].new_key->length,
                    valid_psk_snis.psk_sni_list[i].new_key->s);
                psk_info.hint = *valid_psk_snis.psk_sni_list[i].new_hint;
                psk_info.key = *valid_psk_snis.psk_sni_list[i].new_key;
                break;
            }
        }
    } else {
        coap_log(LOG_DEBUG, "SNI not requested\n");
    }
    return &psk_info;
}

static const coap_bin_const_t * verify_id_callback(coap_bin_const_t *identity,
                   coap_session_t *c_session,
                   void *arg UNUSED_PARAM) 
{
    static coap_bin_const_t psk_key;
    size_t i;

    coap_log(LOG_INFO, "Identity '%.*s' requested, current hint '%.*s'\n", 
            (int) identity->length, identity->s,
            c_session->psk_hint ? (int)c_session->psk_hint->length : 0,
            c_session->psk_hint ? (const char *)c_session->psk_hint->s : "");

    for (i = 0; i < valid_ids.count; i++) {
        /* Check for hint match */
        if (c_session->psk_hint && strcmp((const char *)c_session->psk_hint->s,
                valid_ids.id_list[i].hint_match)) {
            continue;
        }
        /* Test for identity match to change key */
        if (coap_binary_equal(identity, valid_ids.id_list[i].identity_match)) {
            coap_log(LOG_INFO, "Switching to using '%.*s' key\n",
                (int) valid_ids.id_list[i].new_key->length,
                valid_ids.id_list[i].new_key->s);
            return valid_ids.id_list[i].new_key;
        }
    }

    if (c_session->psk_key) {
        /* Been updated by SNI callback */
        psk_key = *c_session->psk_key;
        return &psk_key;
    }

    /* Just use the defined keys for now */
    psk_key.s = key;
    psk_key.length = key_length;
    return &psk_key;
}

static void fill_keystore(coap_context_t *ctx) {
    if (cert_file == NULL && key_defined == 0) {
        if (coap_dtls_is_supported() || coap_tls_is_supported()) {
            coap_log(LOG_DEBUG, "(D)TLS not enabled as neither -k or -c options specified\n");
        }
    }
    if (cert_file) {
        coap_dtls_pki_t dtls_pki;
        memset (&dtls_pki, 0, sizeof(dtls_pki));
        dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
        if (ca_file) {
            /*
            * Add in additional certificate checking.
            * This list of enabled can be tuned for the specific
            * requirements - see 'man coap_encryption'.
            */
            dtls_pki.verify_peer_cert        = 1;
            dtls_pki.require_peer_cert       = require_peer_cert;
            dtls_pki.allow_self_signed       = 1;
            dtls_pki.allow_expired_certs     = 1;
            dtls_pki.cert_chain_validation   = 1;
            dtls_pki.cert_chain_verify_depth = 2;
            dtls_pki.check_cert_revocation   = 1;
            dtls_pki.allow_no_crl            = 1;
            dtls_pki.allow_expired_crl       = 1;
            dtls_pki.validate_cn_call_back   = verify_cn_callback;
            dtls_pki.cn_call_back_arg        = NULL;
            dtls_pki.validate_sni_call_back  = verify_pki_sni_callback;
            dtls_pki.sni_call_back_arg       = NULL;
        }
        if (!use_pem_buf) {
            dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
            dtls_pki.pki_key.key.pem.public_cert = cert_file;
            dtls_pki.pki_key.key.pem.private_key = cert_file;
            dtls_pki.pki_key.key.pem.ca_file = ca_file;
        } else {
            ca_mem = read_file_mem(ca_file, &ca_mem_len);
            cert_mem = read_file_mem(cert_file, &cert_mem_len);
            dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
            dtls_pki.pki_key.key.pem_buf.ca_cert = ca_mem;
            dtls_pki.pki_key.key.pem_buf.public_cert = cert_mem;
            dtls_pki.pki_key.key.pem_buf.private_key = cert_mem;
            dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_mem_len;
            dtls_pki.pki_key.key.pem_buf.public_cert_len = cert_mem_len;
            dtls_pki.pki_key.key.pem_buf.private_key_len = cert_mem_len;
        }

        /* If general root CAs are defined */
        if (root_ca_file) {
            struct stat stbuf;
            if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
                coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
            } else {
                coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
            }
        }
        coap_context_set_pki(ctx, &dtls_pki);
    }
    if (key_defined) {
        coap_dtls_spsk_t dtls_psk;
        memset (&dtls_psk, 0, sizeof(dtls_psk));
        dtls_psk.version = COAP_DTLS_SPSK_SETUP_VERSION;
        dtls_psk.validate_id_call_back = valid_ids.count ? verify_id_callback : NULL;
        dtls_psk.validate_sni_call_back = valid_psk_snis.count ? verify_psk_sni_callback : NULL;
        dtls_psk.psk_info.hint.s = (const uint8_t *)hint;
        dtls_psk.psk_info.hint.length = hint ? strlen(hint) : 0;
        dtls_psk.psk_info.key.s = key;
        dtls_psk.psk_info.key.length = key_length;
        coap_context_set_psk2(ctx, &dtls_psk);
    }
}

/*******************************************************************************
 * @section Help text
 ******************************************************************************/

static void usage(const char *program, const char *version) 
{
    const char *p;
    char buffer[64];

    p = strrchr( program, '/' );
    if ( p ) program = ++p;

    fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
        "(c) 2010,2011,2015-2020 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
        "%s\n\n"
        "Usage: %s [-d directory] [-g group] [-l loss] [-p port] [-v num]\n"
        "\t\t[-A address] [-N]\n"
        "\t\t[[-h hint] [-i match_identity_file] [-k key]\n"
        "\t\t[-s match_psk_sni_file]]\n"
        "\t\t[[-c certfile] [-C cafile] [-m] [-n] [-R root_cafile]]\n"
        "\t\t[-S match_pki_sni_file]]\n"
        "General Options\n"
        "\t-d directory\tLoad files from this directory as GET resources.\n"
        "\t-g group\tJoin the given multicast group\n"
        "\t-l list\t\tFail to send some datagrams specified by a comma\n"
        "\t       \t\tseparated list of numbers or number ranges\n"
        "\t       \t\t(for debugging only)\n"
        "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
        "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
        "\t       \t\t(for debugging only)\n"
        "\t-p port\t\tListen on specified port\n"
        "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
        "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL logging\n"
        "\t-A address\tInterface address to bind to\n"
        "\t-N     \t\tMake \"observe\" responses NON-confirmable. Even if set\n"
        "\t       \t\tevery fifth response will still be sent as a confirmable\n"
        "\t       \t\tresponse (RFC 7641 requirement)\n"
        "PSK Options (if supported by underlying (D)TLS library)\n"
        "\t-h hint\t\tIdentity Hint. Default is CoAP. Zero length is no hint\n"
        "\t-i match_identity_file\n"
        "\t       \t\tThis option denotes a file that contains one or more lines\n"
        "\t       \t\tof client Hints and (user) Identities to match for a new\n"
        "\t       \t\tPre-Shared Key (PSK) (comma separated) to be used. E.g.,\n"
        "\t       \t\tper line\n"
        "\t       \t\t hint_to_match,identity_to_match,new_key\n"
        "\t       \t\tNote: -k still needs to be defined for the default case\n"
        "\t-k key \t\tPre-Shared Key. This argument requires (D)TLS with PSK\n"
        "\t       \t\tto be available. This cannot be empty if defined.\n"
        "\t       \t\tNote that both -c and -k need to be defined\n"
        "\t       \t\tfor both PSK and PKI to be concurrently supported\n"
        "\t-s match_psk_sni_file\n"
        "\t       \t\tThis is a file that contains one or more lines of Subject\n"
        "\t       \t\tName Identifiers (SNI) to match for new Identity Hint and\n"
        "\t       \t\tnew Pre-Shared Key (PSK) (comma separated) to be used.\n"
        "\t       \t\tE.g., per line\n"
        "\t       \t\t sni_to_match,new_hint,new_key\n"
        "\t       \t\tNote: -k still needs to be defined for the default case\n"
        "\t       \t\tNote: the new Pre-Shared Key will get updated if there is\n"
        "\t       \t\talso a -i match\n"
        "PKI Options (if supported by underlying (D)TLS library)\n"
        "\t-c certfile\tPEM file containing both CERTIFICATE and PRIVATE KEY\n"
        "\t       \t\tThis argument requires (D)TLS with PKI to be available\n"
        "\t-m     \t\tUse COAP_PKI_KEY_PEM_BUF instead of COAP_PKI_KEY_PEM i/f\n"
        "\t       \t\tby reading in the Cert / CA file (for testing)\n"
        "\t-n     \t\tDisable the requirement for clients to have defined\n"
        "\t       \t\tclient certificates\n"
        "\t-C cafile\tPEM file containing the CA Certificate that was used to\n"
        "\t       \t\tsign the certfile. If defined, then the client will be\n"
        "\t       \t\tgiven this CA Certificate during the TLS set up.\n"
        "\t       \t\tFurthermore, this will trigger the validation of the\n"
        "\t       \t\tclient certificate.  If certfile is self-signed (as\n"
        "\t       \t\tdefined by '-c certfile'), then you need to have on the\n"
        "\t       \t\tcommand line the same filename for both the certfile and\n"
        "\t       \t\tcafile (as in  '-c certfile -C certfile') to trigger\n"
        "\t       \t\tvalidation\n"
        "\t-R root_cafile\tPEM file containing the set of trusted root CAs that\n"
        "\t       \t\tare to be used to validate the client certificate.\n"
        "\t       \t\tThe '-C cafile' does not have to be in this list and is\n"
        "\t       \t\t'trusted' for the verification.\n"
        "\t       \t\tAlternatively, this can point to a directory containing\n"
        "\t       \t\ta set of CA PEM files\n"
        "\t-S match_pki_sni_file\n"
        "\t       \t\tThis option denotes a file that contains one or more lines\n"
        "\t       \t\tof Subject Name Identifier (SNI) to match for new Cert\n"
        "\t       \t\tfile and new CA file (comma separated) to be used.\n"
        "\t       \t\tE.g., per line\n"
        "\t       \t\t sni_to_match,new_cert_file,new_ca_file\n"
        "\t       \t\tNote: -c and -C still needs to be defined for the default case\n"
    , program, version, coap_string_tls_version(buffer, sizeof(buffer)), program);
}
    
/*******************************************************************************
 * @section Context handling
 ******************************************************************************/

static coap_context_t * get_context(const char *node, const char *port) 
{
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    
    ctx = coap_new_context(NULL);
    if (!ctx) return NULL;

    /* Need PSK set up before we set up (D)TLS endpoints */
    fill_keystore(ctx);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    
    s = getaddrinfo(node, port, &hints, &result);
    if ( s != 0 ) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        coap_free_context(ctx);
        return NULL;
    }

    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t addr, addrs;
        coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL;

        if (rp->ai_addrlen <= sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = (socklen_t)rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
            addrs = addr;
            if (addr.addr.sa.sa_family == AF_INET) {
                uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
                addrs.addr.sin.sin_port = htons(temp);
            } else if (addr.addr.sa.sa_family == AF_INET6) {
                uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
                addrs.addr.sin6.sin6_port = htons(temp);
            } else {
                goto finish;
            }
    
            ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
            if (ep_udp) {
                if (coap_dtls_is_supported() && (key_defined || cert_file)) {
                    ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
                    if (!ep_dtls)
                        coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
                }
            } else {
                coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
                continue;
            }
            if (coap_tcp_is_supported()) {
                coap_endpoint_t *ep_tcp;
                ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
                if (ep_tcp) {
                    if (coap_tls_is_supported() && (key_defined || cert_file)) {
                        coap_endpoint_t *ep_tls;
                        ep_tls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_TLS);
                        if (!ep_tls)
                            coap_log(LOG_CRIT, "cannot create TLS endpoint\n");
                    }
                } else {
                    coap_log(LOG_CRIT, "cannot create TCP endpoint\n");
                }
            }
            if (ep_udp) goto finish;
        }
    }

    fprintf(stderr, "no context available for interface '%s'\n", node);
    coap_free_context(ctx);
    ctx = NULL;

finish:
    freeaddrinfo(result);
    return ctx;
}

/*******************************************************************************
 * @section Command line parsing
 ******************************************************************************/

static ssize_t cmdline_read_key(char *arg, unsigned char *buf, size_t maxlen) 
{
    size_t len = strnlen(arg, maxlen);
    if (len) {
        memcpy(buf, arg, len);
        return len;
    }
    return -1;
}

static int cmdline_read_psk_sni_check(char *arg) 
{
    FILE *fp = fopen(arg, "r");
    static char tmpbuf[256];
    if (fp == NULL) {
        coap_log(LOG_ERR, "SNI file: %s: Unable to open\n", arg);
        return 0;
    }
    while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
        char *cp = tmpbuf;
        char *tcp = strchr(cp, '\n');
    
        if (tmpbuf[0] == '#') continue;
        if (tcp) *tcp = '\000';
    
        tcp = strchr(cp, ',');
        if (tcp) {
            psk_sni_def_t *new_psk_sni_list;
            new_psk_sni_list = realloc(valid_psk_snis.psk_sni_list,
                (valid_psk_snis.count + 1)*sizeof (valid_psk_snis.psk_sni_list[0]));
            if (new_psk_sni_list == NULL) {
                break;
            }
            valid_psk_snis.psk_sni_list = new_psk_sni_list;
            valid_psk_snis.psk_sni_list[valid_psk_snis.count].sni_match = strndup(cp, tcp-cp);
            cp = tcp+1;
            tcp = strchr(cp, ',');
            if (tcp) {
                valid_psk_snis.psk_sni_list[valid_psk_snis.count].new_hint =
                            coap_new_bin_const((const uint8_t *)cp, tcp-cp);
                cp = tcp+1;
                valid_psk_snis.psk_sni_list[valid_psk_snis.count].new_key =
                            coap_new_bin_const((const uint8_t *)cp, strlen(cp));
                valid_psk_snis.count++;
            } else {
                free(valid_psk_snis.psk_sni_list[valid_psk_snis.count].sni_match);
            }
        }
    }
    fclose(fp);
    return valid_psk_snis.count > 0;
}

static int cmdline_read_identity_check(char *arg) 
{
    FILE *fp = fopen(arg, "r");
    static char tmpbuf[256];
    if (fp == NULL) {
        coap_log(LOG_ERR, "Identity file: %s: Unable to open\n", arg);
        return 0;
    }
    while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
        char *cp = tmpbuf;
        char *tcp = strchr(cp, '\n');

        if (tmpbuf[0] == '#') continue;
        if (tcp) *tcp = '\000';

        tcp = strchr(cp, ',');
        if (tcp) {
            id_def_t *new_id_list;
            new_id_list = realloc(valid_ids.id_list,
                          (valid_ids.count + 1)*sizeof (valid_ids.id_list[0]));
            if (new_id_list == NULL) {
                break;
            }
            valid_ids.id_list = new_id_list;
            valid_ids.id_list[valid_ids.count].hint_match = strndup(cp, tcp-cp);
            cp = tcp+1;
            tcp = strchr(cp, ',');
            if (tcp) {
                valid_ids.id_list[valid_ids.count].identity_match =
                            coap_new_bin_const((const uint8_t *)cp, tcp-cp);
                cp = tcp+1;
                valid_ids.id_list[valid_ids.count].new_key =
                            coap_new_bin_const((const uint8_t *)cp, strlen(cp));
                valid_ids.count++;
            } else {
                free(valid_ids.id_list[valid_ids.count].hint_match);
            }
        }
    }
    fclose(fp);
    return valid_ids.count > 0;
}

static int cmdline_read_pki_sni_check(char *arg)
{
    FILE *fp = fopen(arg, "r");
    static char tmpbuf[256];
    if (fp == NULL) {
        coap_log(LOG_ERR, "SNI file: %s: Unable to open\n", arg);
        return 0;
    }
    while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
        char *cp = tmpbuf;
        char *tcp = strchr(cp, '\n');

        if (tmpbuf[0] == '#') continue;
        if (tcp) *tcp = '\000';

        tcp = strchr(cp, ',');
        if (tcp) {
            pki_sni_def_t *new_pki_sni_list;
            new_pki_sni_list = realloc(valid_pki_snis.pki_sni_list,
                (valid_pki_snis.count + 1)*sizeof (valid_pki_snis.pki_sni_list[0]));
            if (new_pki_sni_list == NULL) break;
            valid_pki_snis.pki_sni_list = new_pki_sni_list;
            valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match = strndup(cp, tcp-cp);
            cp = tcp+1;
            tcp = strchr(cp, ',');
            if (tcp) {
                int fail = 0;
                valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert = strndup(cp, tcp-cp);
                cp = tcp+1;
                valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca =
                             strndup(cp, strlen(cp));
                if (access(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert, R_OK)) {
                    coap_log(LOG_ERR, "SNI file: Cert File: %s: Unable to access\n",
                        valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert);
                    fail = 1;
                }
                if (access(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca, R_OK)) {
                    coap_log(LOG_ERR, "SNI file: CA File: %s: Unable to access\n",
                        valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca);
                    fail = 1;
                }
                if (fail) {
                    free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match);
                    free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert);
                    free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca);
                } else {
                    valid_pki_snis.count++;
                }
            } else {
                coap_log(LOG_ERR, "SNI file: SNI_match,Use_Cert_file,Use_CA_file not defined\n");
                free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match);
            }
        }
    }
    fclose(fp);
    return valid_pki_snis.count > 0;
}

int main(int argc, char **argv) 
{
    coap_context_t  *ctx;
    char *group = NULL;
    coap_tick_t now;
    char addr_str[NI_MAXHOST] = "::";
    char port_str[NI_MAXSERV] = "5683";
    int opt;
    coap_log_t log_level = LOG_WARNING;
    unsigned wait_ms;
    coap_time_t t_last = 0;
    int coap_fd;
    fd_set m_readfds;
    int nfds = 0;
    size_t i;
#ifndef _WIN32
    struct sigaction sa;
#endif

    while ((opt = getopt(argc, argv, "A:d:c:C:g:h:i:k:l:mnNp:R:s:S:v:")) != -1) {
        switch (opt) {
        case 'A' :
            strncpy(addr_str, optarg, NI_MAXHOST-1);
            addr_str[NI_MAXHOST - 1] = '\0';
            break;
        case 'c' :
            cert_file = optarg;
            break;
        case 'C' :
            ca_file = optarg;
            break;
        case 'd' :
            fsdir = optarg;
            break;
        case 'g' :
            group = optarg;
            break;
        case 'h' :
            if (!optarg[0]) {
                hint = NULL;
                break;
            }
            hint = optarg;
            break;
        case 'i':
            if (!cmdline_read_identity_check(optarg)) {
                usage(argv[0], LIBCOAP_PACKAGE_VERSION);
                exit(1);
            }
            break;
        case 'k' :
            key_length = cmdline_read_key(optarg, key, MAX_KEY);
            if (key_length < 0) {
                coap_log( LOG_CRIT, "Invalid Pre-Shared Key specified\n" );
                break;
            }
            key_defined = 1;
            break;
        case 'l':
            if (!coap_debug_set_packet_loss(optarg)) {
                usage(argv[0], LIBCOAP_PACKAGE_VERSION);
                exit(1);
            }
            break;
        case 'm':
            use_pem_buf = 1;
            break;
        case 'n':
            require_peer_cert = 0;
            break;
        case 'N':
            resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_NON;
            break;
        case 'p' :
            strncpy(port_str, optarg, NI_MAXSERV-1);
            port_str[NI_MAXSERV - 1] = '\0';
            break;
        case 'R' :
            root_ca_file = optarg;
            break;
        case 's':
            if (!cmdline_read_psk_sni_check(optarg)) {
                usage(argv[0], LIBCOAP_PACKAGE_VERSION);
                exit(1);
            }
            break;
        case 'S':
            if (!cmdline_read_pki_sni_check(optarg)) {
                usage(argv[0], LIBCOAP_PACKAGE_VERSION);
                exit(1);
            }
            break;
        case 'v' :
            log_level = strtol(optarg, NULL, 10);
            break;
        default:
            usage( argv[0], LIBCOAP_PACKAGE_VERSION );
            exit(1);
        }
    }

    coap_startup();
    coap_dtls_set_log_level(log_level);
    coap_set_log_level(log_level);
    
    ctx = get_context(addr_str, port_str);
    if (!ctx) return -1;

    init_resources(ctx);

    /* join multicast group if requested at command line */
    if (group) coap_join_mcast_group(ctx, group);

    coap_fd = coap_context_get_coap_fd(ctx);
    if (coap_fd != -1) {
        /* if coap_fd is -1, then epoll is not supported within libcoap */
        FD_ZERO(&m_readfds);
        FD_SET(coap_fd, &m_readfds);
        nfds = coap_fd + 1;
    }

#ifdef _WIN32
    signal(SIGINT, handle_sigint);
#else
    memset (&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigaction (SIGINT, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);
    /* So we do not exit on a SIGPIPE */
    sa.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &sa, NULL);
#endif

    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

    while ( !quit ) {
        int result;

        if (coap_fd != -1) {
            /*
            * Using epoll.  It is more usual to call coap_io_process() with wait_ms
            * (as in the non-epoll branch), but doing it this way gives the
            * flexibility of potentially working with other file descriptors that
            * are not a part of libcoap.
            */
            fd_set readfds = m_readfds;
            struct timeval tv;
            coap_tick_t begin, end;

            coap_ticks(&begin);

            tv.tv_sec = wait_ms / 1000;
            tv.tv_usec = (wait_ms % 1000) * 1000;
            /* Wait until any i/o takes place or timeout */
            result = select (nfds, &readfds, NULL, NULL, &tv);
            if (result == -1) {
                if (errno != EAGAIN) {
                    coap_log(LOG_DEBUG, "select: %s (%d)\n", coap_socket_strerror(), errno);
                    break;
                }
            }
            if (result > 0) {
                if (FD_ISSET(coap_fd, &readfds)) {
                    result = coap_io_process(ctx, COAP_IO_NO_WAIT);
                }
            }
            if (result >= 0) {
                coap_ticks(&end);
                /* Track the overall time spent in select() and coap_io_process() */
                result = (int)(end - begin);
            }
        } else {
            /*
            * epoll is not supported within libcoap
            *
            * result is time spent in coap_io_process()
            */
            result = coap_io_process(ctx, wait_ms);
        }
        if (result < 0) {
            break;
        } else if ( result && (unsigned)result < wait_ms ) {
            /* decrement if there is a result wait time returned */
            wait_ms -= result;
        } else {
            /*
            * result == 0, or result >= wait_ms
            * (wait_ms could have decremented to a small value, below
            * the granularity of the timer in coap_io_process() and hence
            * result == 0)
            */
            wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
        }

    }

    if (ca_mem) free(ca_mem);
    if (cert_mem) free(cert_mem);
    for (i = 0; i < valid_psk_snis.count; i++) {
        free(valid_psk_snis.psk_sni_list[i].sni_match);
        coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_hint);
        coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_key);
    }
    if (valid_psk_snis.count) free(valid_psk_snis.psk_sni_list);
    for (i = 0; i < valid_ids.count; i++) {
        free(valid_ids.id_list[i].hint_match);
        coap_delete_bin_const(valid_ids.id_list[i].identity_match);
        coap_delete_bin_const(valid_ids.id_list[i].new_key);
    }
    if (valid_ids.count) free(valid_ids.id_list);
    for (i = 0; i < valid_pki_snis.count; i++) {
        free(valid_pki_snis.pki_sni_list[i].sni_match);
        free(valid_pki_snis.pki_sni_list[i].new_cert);
        free(valid_pki_snis.pki_sni_list[i].new_ca);
    }
    if (valid_pki_snis.count) free(valid_pki_snis.pki_sni_list);

    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}
