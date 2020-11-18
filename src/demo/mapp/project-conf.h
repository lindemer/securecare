/*
 * Copyright (c) 2020, RISE.
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
 */

#ifndef PROJECT_CONF_H
#define PROJECT_CONF_H

#include "est.h"
#include "rplidar.h"

#undef MBEDTLS_CHACHAPOLY_C
#undef MBEDTLS_CHACHA20_C

#define COAPS_DFU_DTLS_ENABLE 1

// Remote EST server parameters.
//static const uint8_t est_remote_addr[16] =
//        { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

/*
 * EST address + path info
 */
#ifdef EST_WITH_NEXUS
#define CRTS_PATH ".well-known/est/coap/crts"
#define SEN_PATH ".well-known/est/coap/sen"
#define SKG_PATH ".well-known/est/coap/skg"

static const uint8_t est_remote_addr[16] =
        { 0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x33, 0x7c, 0x15, 0x51 };
//NEXUS 51.124.21.81 --> 64:ff9b::33:7c:15:51

#else
#define CRTS_PATH "crts"
#define SEN_PATH "sen"
#define SKG_PATH "skg"

/*
 * Warning: this needs to be updated for the target deployment!
 */
static const uint8_t est_remote_addr[16] =
  { 0xfd, 0x11, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00,
    0x82, 0xe6, 0x03, 0x3b, 0xe7, 0x2b, 0xf8, 0x9e };
//fd11:22::82e6:33b:e72b:f89e

#endif

/*
 * SUIT path info
 */
// Remote SUIT resource URNs
#define manifest_resource_name  "manifest.cbor"
//static char * manifest_resource_name = "manifest.cbor";


#define DEMO_NODE_KEY \
 "-----BEGIN EC PRIVATE KEY-----\r\n"  \
 "MHcCAQEEIIEAWPDa5w9nzetMrydKRi5rCWujCy+xVPYOu2tP3Ry3oAoGCCqGSM49\r\n"  \
 "AwEHoUQDQgAExdc54hhS6jblb24HdYyHW1UwOoZ5p5ajRkcW2Dz/6ijh29DF67Xw\r\n"  \
 "kH9u/BGWUCgee6D2WplfazZ+8uTaJx59wg==\r\n"  \
 "-----END EC PRIVATE KEY-----\r\n"


#if !HAVE_RANDOM
//"28eaff.." is the public key corresponding to DEMO_NODE_KEY
__ALIGN(4) static const uint8_t demo_node_key_pub[64] =
{
    0x28, 0xea, 0xff, 0x3c, 0xd8, 0x16, 0x47, 0x46, 0xa3, 0x96, 0xa7, 0x79, 0x86, 0x3a, 0x30, 0x55, 0x5b, 0x87, 0x8c, 0x75, 0x07, 0x6e, 0x6f, 0xe5, 0x36, 0xea, 0x52, 0x18, 0xe2, 0x39, 0xd7, 0xc5,
    0xc2, 0x7d, 0x1e, 0x27, 0xda, 0xe4, 0xf2, 0x7e, 0x36, 0x6b, 0x5f, 0x99, 0x5a, 0xf6, 0xa0, 0x7b, 0x1e, 0x28, 0x50, 0x96, 0x11, 0xfc, 0x6e, 0x7f, 0x90, 0xf0, 0xb5, 0xeb, 0xc5, 0xd0, 0xdb, 0xe1
};

////"0bc7ae.." is the public key corresponding to PRIVATE_ENROLLMENT_KEY
//__ALIGN(4) const uint8_t ek_pub[64] =
//{
//    0x0b, 0xc7, 0xae, 0x60, 0x68, 0x21, 0xf3, 0x0a, 0x2d, 0x17, 0x52, 0xf5, 0x12, 0x3b, 0x77, 0x66, 0x6d, 0xf9, 0xab, 0x18, 0x46, 0x15, 0xdd, 0x29, 0xf5, 0xe3, 0x02, 0xf8, 0xb3, 0xef, 0x3f, 0xb6,
//    0x7b, 0xfb, 0x2c, 0xce, 0x50, 0x2b, 0x64, 0x85, 0x9a, 0x16, 0x8f, 0x08, 0x7f, 0x8d, 0xfd, 0xe4, 0x02, 0xef, 0xdb, 0xa2, 0x1e, 0x5b, 0xc6, 0x25, 0x07, 0xab, 0x11, 0x6a, 0xfb, 0x8a, 0xb7, 0xda
//};

//b71cdd4f6bbb0ef654b12f0ba36b096b2e464a27af4cebcd670fe7daf0580081 is the private key in DEMO_NODE_KEY
__ALIGN(4) static const uint8_t demo_node_key_priv[32] =
{
    0xb7,0x1c,0xdd,0x4f,0x6b,0xbb,0x0e,0xf6,0x54,0xb1,0x2f,0x0b,0xa3,0x6b,0x09,0x6b,0x2e,0x46,0x4a,0x27,0xaf,0x4c,0xeb,0xcd,0x67,0x0f,0xe7,0xda,0xf0,0x58,0x00,0x81
};


//4d776454cd49c1827d0b4d3b89ef20b28ff2cf8c0ec8cb686e4d0067a0307d15 is the private key in PRIVATE_ENROLLMENT_KEY
//__ALIGN(4) const uint8_t ek_priv[32] =
//{
//    0x4d,0x77,0x64,0x54,0xcd,0x49,0xc1,0x82,0x7d,0x0b,0x4d,0x3b,0x89,0xef,0x20,0xb2,0x8f,0xf2,0xcf,0x8c,0x0e,0xc8,0xcb,0x68,0x6e,0x4d,0x00,0x67,0xa0,0x30,0x7d,0x15
//};

//{
//    0x83,0x49,0x32,0xed,0x4e,0xe1,0xaa,0x71,0x70,0x35,0x44,0x7e,0x29,0xa2,0x3e,0x90,0x81,0xd6,0x69,0xd5,0xc2,0x94,0x6b,0xda,0x5d,0x8f,0x98,0x10,0x50,0xa4,0x8d,0xcb
//};

#endif //test keys for running node without RNG


#ifdef EST_WITH_NEXUS


#define FACTORY_CERT      \
"-----BEGIN CERTIFICATE-----\r\n"  \
"MIIBoDCCAUagAwIBAgICJyYwCgYIKoZIzj0EAwIwSDELMAkGA1UEBhMCU0UxEjAQ\r\n" \
"BgNVBAoTCUVTVC1Db0FQUzElMCMGA1UEAxMcRVNULUNvQVBTIEZhY3RvcnkgaXNz\r\n" \
"dWluZyBDQTAeFw0yMDA2MDUxOTQzMzZaFw0yMjA2MDUxOTQzMzZaMEQxCzAJBgNV\r\n" \
"BAYTAlNFMRIwEAYDVQQKEwlFU1QtQ29BUFMxITAfBgNVBAMTGEVTVC1Db0FQUyBk\r\n" \
"ZXZpY2UgZmFjdG9yeTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHhvEgPTjndY\r\n" \
"dqeQ9+UIY2ad1YtZI0EKqrsQ17GGU+UUd8HvOvOPJB0C/TAXdhwJ5UZG8Okxi/+w\r\n" \
"0s6VvrNq+rOjJDAiMBMGA1UdIwQMMAqACE9yT+TlkphaMAsGA1UdDwQEAwIFoDAK\r\n" \
"BggqhkjOPQQDAgNIADBFAiEA+uQyCrqzjiA9iTpElFZparAKWzrNf88It2KZfolq\r\n" \
"2loCIEzCr4urMrHI01StbzlswedxZ9/gmx2TR+NlS21COz9l\r\n" \
"-----END CERTIFICATE-----\r\n"

#define FACTORY_KEY   \
"-----BEGIN PRIVATE KEY-----\r\n"   \
"MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCyyknSAw+YwAK745Vp\r\n"  \
"gBR8tZl2yu8XHwHZNK1cxvDk1g==\r\n"  \
"-----END PRIVATE KEY-----\r\n"



#define ROOT_CA_CERT \
 "-----BEGIN CERTIFICATE-----\r\n"   \
 "MIIBkjCCATmgAwIBAgICJxwwCgYIKoZIzj0EAwIwODELMAkGA1UEBhMCU0UxEjAQ\r\n"  \
 "BgNVBAoTCUVTVC1Db0FQUzEVMBMGA1UEAxMMRVNULUNvQVBTIENBMB4XDTIwMDYw\r\n"  \
 "NTE5NDMyN1oXDTI1MDYwNTE3NDMyN1owODELMAkGA1UEBhMCU0UxEjAQBgNVBAoT\r\n"  \
 "CUVTVC1Db0FQUzEVMBMGA1UEAxMMRVNULUNvQVBTIENBMFkwEwYHKoZIzj0CAQYI\r\n"  \
 "KoZIzj0DAQcDQgAEzeSzSReaFHPk6166dCW2aafaKIiOlCM4ZP3VxfLmmj2Q8q8L\r\n"  \
 "AYQh7xbyIEnq8p+bo3W3YMsgNz8GwDtepqD8SqMzMDEwDwYDVR0TAQH/BAUwAwEB\r\n"  \
 "/zARBgNVHQ4ECgQIRi0+wat3BfIwCwYDVR0PBAQDAgEGMAoGCCqGSM49BAMCA0cA\r\n"  \
 "MEQCICO9hiAzg7+9vBojLbx44aN4FqsaNcvscxoB51dV729HAiBACvbJXMCz6zt7\r\n"  \
 "a4cENvzB9HiZoSpqbwSYUEZdkGIfkA==\r\n"  \
 "-----END CERTIFICATE-----\r\n"


#define I_CA_CERT \
 "-----BEGIN CERTIFICATE-----\r\n"  \
 "MIIBsTCCAVagAwIBAgICJx0wCgYIKoZIzj0EAwIwODELMAkGA1UEBhMCU0UxEjAQ\r\n"  \
 "BgNVBAoTCUVTVC1Db0FQUzEVMBMGA1UEAxMMRVNULUNvQVBTIENBMB4XDTIwMDYw\r\n"  \
 "NTE5NDMyOFoXDTI1MDYwNTE3NDMyN1owQDELMAkGA1UEBhMCU0UxEjAQBgNVBAoT\r\n"  \
 "CUVTVC1Db0FQUzEdMBsGA1UEAxMURVNULUNvQVBTIGlzc3VpbmcgQ0EwWTATBgcq\r\n"  \
 "hkjOPQIBBggqhkjOPQMBBwNCAAS/XVji5qoI0ZUpHXRSdHjVv+MthvW7JQX9+bqI\r\n"  \
 "dYnnQ+I7shDueFO06Fi1vflQcLvbgcAbx+/dEK/kyAubJFHKo0gwRjAPBgNVHRMB\r\n"  \
 "Af8EBTADAQH/MBEGA1UdDgQKBAhGAUBdRFLUwzATBgNVHSMEDDAKgAhGLT7Bq3cF\r\n"  \
 "8jALBgNVHQ8EBAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhAKHULL0kmYBucUhoVbDV\r\n"  \
 "Ig3Dv+acemPFBcspLE0gI5WFAiEApqPdhGRWhQjok7vpopMB5HfJRP7VlkSi3wNo\r\n"  \
 "Egvkp4o=\r\n"  \
 "-----END CERTIFICATE-----\r\n"

//Internet says "root at the bottom", at least for your own chain: https://www.digicert.com/kb/ssl-support/pem-ssl-creation.htm

//#define INITIAL_TRUSTSTORE I_CA_CERT
//#define INITIAL_TRUSTSTORE I_CA_CERT""ROOT_CA_CERT
#define INITIAL_TRUSTSTORE ROOT_CA_CERT""I_CA_CERT //== 1279
//"\r\n"ROOT_CA_CERT

#define CA_CERT_STRING "MIIBkjCCATmgAwIBAgICJxwwCgYIKoZIzj0EAwIwODELMAkGA1UEBhMCU0UxEjAQBgNVBAoTCUVTVC1Db0FQUzEVMBMGA1UEAxMMRVNULUNvQVBTIENBMB4XDTIwMDYwNTE5NDMyN1oXDTI1MDYwNTE3NDMyN1owODELMAkGA1UEBhMCU0UxEjAQBgNVBAoTCUVTVC1Db0FQUzEVMBMGA1UEAxMMRVNULUNvQVBTIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzeSzSReaFHPk6166dCW2aafaKIiOlCM4ZP3VxfLmmj2Q8q8LAYQh7xbyIEnq8p+bo3W3YMsgNz8GwDtepqD8SqMzMDEwDwYDVR0TAQH/BAUwAwEB/zARBgNVHQ4ECgQIRi0+wat3BfIwCwYDVR0PBAQDAgEGMAoGCCqGSM49BAMCA0cAMEQCICO9hiAzg7+9vBojLbx44aN4FqsaNcvscxoB51dV729HAiBACvbJXMCz6zt7a4cENvzB9HiZoSpqbwSYUEZdkGIfkA=="


#else //EST with RISE test EST server
#pragma message "Do you want to run the local EST server?"
//Check lib/mbedtls/library/certs.c for formatting
#define FACTORY_CERT      \
 "-----BEGIN CERTIFICATE-----\r\n"                                        \
 "MIIBNzCB3qADAgECAgMB9Q0wCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLUkZDIHRl\r\n"   \
 "c3QgQ0EwHhcNMjAwMTAxMDAwMDAwWhcNMjEwMjAyMDAwMDAwWjAiMSAwHgYDVQQD\r\n"   \
 "DBcwMS0yMy00NS1GRi1GRS02Ny04OS1BQjBZMBMGByqGSM49AgEGCCqGSM49AwEH\r\n"   \
 "A0IABK5M2wH2FN78cSEoX9x/XG0dQslWR/BhugCA32eIZ4Re6aaf1IkxSdrj07FU\r\n"   \
 "FtdTLDhxUrgLDfPhr0CKldMHHlijDzANMAsGA1UdDwQEAwIHgDAKBggqhkjOPQQD\r\n"   \
 "AgNIADBFAiBpCx7E3Axdp7fnPNISqUa1vbsm7XG2rnbCEKCdX3VVhQIhALYVEniy\r\n"   \
 "+GuSR1wIDWiDD6wbdMIBqt1i+1lqt6ZLypCz\r\n"   \
 "-----END CERTIFICATE-----\r\n"

#define FACTORY_CERT_LEN 491

#define FACTORY_KEY   \
 "-----BEGIN EC PRIVATE KEY-----\r\n"   \
 "MHcCAQEEINxms0FUVtZJQptTIj33UyuULWsOCELDC8pMCs+RVHuyoAoGCCqGSM49\r\n"   \
 "AwEHoUQDQgAErkzbAfYU3vxxIShf3H9cbR1CyVZH8GG6AIDfZ4hnhF7ppp/UiTFJ\r\n"   \
 "2uPTsVQW11MsOHFSuAsN8+GvQIqV0wceWA==\r\n"   \
 "-----END EC PRIVATE KEY-----\r\n"

#define FACTORY_KEY_LEN 233

#define INITIAL_TRUSTSTORE    \
 "-----BEGIN CERTIFICATE-----\r\n"   \
 "MIIBczCCARmgAwIBAgIJAM2dR7gJjlllMAoGCCqGSM49BAMCMBYxFDASBgNVBAMM\r\n"   \
 "C1JGQyB0ZXN0IENBMB4XDTIwMDIxOTEwMzcxNVoXDTIyMDIxODEwMzcxNVowFjEU\r\n"   \
 "MBIGA1UEAwwLUkZDIHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASu\r\n"   \
 "TNsB9hTe/HEhKF/cf1xtHULJVkfwYboAgN9niGeEXummn9SJMUna49OxVBbXUyw4\r\n"   \
 "cVK4Cw3z4a9AipXTBx5Yo1AwTjAdBgNVHQ4EFgQUvAQzwQ3fzU8+ltBGwNdu6qGB\r\n"   \
 "zZ4wHwYDVR0jBBgwFoAUvAQzwQ3fzU8+ltBGwNdu6qGBzZ4wDAYDVR0TBAUwAwEB\r\n"   \
 "/zAKBggqhkjOPQQDAgNIADBFAiEAqYQGzIRdffBrhU666iuI5jQnUVBJwCmGCaIQ\r\n"   \
 "kGquoFMCIBeqMznbEtLEDUHJIUiJFFrJM96pbE3xFn3jbfQ1OUte\r\n"   \
 "-----END CERTIFICATE-----\r\n"

#define INITIAL_TRUSTSTORE_LEN 573

#define CA_CERT_STRING "MIIBczCCARmgAwIBAgIJAM2dR7gJjlllMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC1JGQyB0ZXN0IENBMB4XDTIwMDIxOTEwMzcxNVoXDTIyMDIxODEwMzcxNVowFjEUMBIGA1UEAwwLUkZDIHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuTNsB9hTe/HEhKF/cf1xtHULJVkfwYboAgN9niGeEXummn9SJMUna49OxVBbXUyw4cVK4Cw3z4a9AipXTBx5Yo1AwTjAdBgNVHQ4EFgQUvAQzwQ3fzU8+ltBGwNdu6qGBzZ4wHwYDVR0jBBgwFoAUvAQzwQ3fzU8+ltBGwNdu6qGBzZ4wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAqYQGzIRdffBrhU666iuI5jQnUVBJwCmGCaIQkGquoFMCIBeqMznbEtLEDUHJIUiJFFrJM96pbE3xFn3jbfQ1OUte"

#define CUSTOM_SUIT_COAP_SECURE_PORT  5684
#define CUSTOM_EST_COAP_SECURE_PORT   5686//5686

#endif //END of else = local EST testing

/*
 * Good to have: \n --> \\r\\n"\t \\\n "
 */

/*
 * Node/hw specific settings
 */
#define TRUSTSTORE_PARSE_BUFFER_SIZE 1024

#define SENSOR_PERIOD    1000 //ms
#define SENSOR_DATA_PATH "sensor"

//With SENSOR_PRESENT set to 0 the lidar sensor will not be started, the periodic process will send dummy data
#if SENSOR_PRESENT
#pragma message "Assuming lidar sensor present!"
#else
#pragma message "No sensor present"
#endif

/*
 * EST flash settings
 */
static const uint32_t EST_FLASH_START_ADDRESS = 0x0007F000;
static const uint32_t EST_DONE_SYMBOL = 2147483647;
//#define EST_DONE_SYMBOL 4294967295

/*
 * State settings
 */
#define CONFIG_INITIAL_STATE BACKGROUND_EST_IDLE        //Alt. BACKGROUND_PERIODIC_IDLE || BACKGROUND_DFU_IDLE
#define CONFIG_STATE_AFTER_EST BACKGROUND_PERIODIC_IDLE //Alt. BACKGROUND_DFU_IDLE

//CACERTS setting, blockwise = 9
#define BACKGROUND_EST_GET_CACERTS_CONFIG 9

#if TEST_ENROLL_SUBJECT
extern const char client_mac_id[];
#else
extern const uint8_t client_mac_id[];
#endif

#ifdef USE_CBOR_ENCODING
#define EST_CONTENT_FORMAT_FOR_SEN COAP_CONTENT_FORMAT_CBOREN
#else
#define EST_CONTENT_FORMAT_FOR_SEN COAP_CONTENT_FORMAT_PKCS10
#endif


#endif //ifndef PROJECT_CONF_H


