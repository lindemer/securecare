/*
 * Copyright (c) 2020, RISE
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


//#define EST_WITH_NEXUS 1

/*
 * Unless there is a RNG
 */


/*
//Use "MHcCAQEEIBV9..." for the node:
//#define PRIVATE_ENROLLMENT_KEY   \
// "-----BEGIN EC PRIVATE KEY-----\r\n"   \
// "MHcCAQEEIBV9MKBnAE1uaMvIDozP8o+yIO+JO00LfYLBSc1UZHdNoAoGCCqGSM49\r\n"   \
// "AwEHoUQDQgAEtj/vs/gC4/Up3RVGGKv5bWZ3OxL1UhctCvMhaGCuxwvat4r7ahGr\r\n"   \
// "ByXGWx6i2+8C5P2NfwiPFpqFZCtQziz7ew==\r\n"   \
// "-----END EC PRIVATE KEY-----\r\n"
*/

/*
 * EST path info
 */
#ifdef EST_WITH_NEXUS
#define EST_CRTS_URL "coaps://51.124.21.81/.well-known/est/coap/crts"
#define EST_SEN_URL "coaps://51.124.21.81/.well-known/est/coap/sen"
#define CRTS_PATH ".well-known/est/coap/crts"
#define SEN_PATH ".well-known/est/coap/sen"
#define SKG_PATH ".well-known/est/coap/skg"
#else
#define EST_CRTS_URL "coaps://[localhost]/crts"
#define EST_SEN_URL "coaps://[localhost]/sen"
#define CRTS_PATH "crts"
#define SEN_PATH "sen"
#define SKG_PATH "skg"
#endif


#ifdef EST_WITH_NEXUS

//#define FACTORY_CERT_PATH "/home/ubuntu/eclipse-workspace/securecare/nexus/nexus_factory_cert.pem"
//#define CA_CERT_PATH      "/home/ubuntu/eclipse-workspace/securecare/nexus/ts/"
//#define CA_CERT_STRING "NULL" //empty, should not be used!
//#define CA_CERT_STRING "MIIBkjCCATmgAwIBAgICJxwwCgYIKoZIzj0EAwIwODELMAkGA1UEBhMCU0UxEjAQBgNVBAoTCUVTVC1Db0FQUzEVMBMGA1UEAxMMRVNULUNvQVBTIENBMB4XDTIwMDYwNTE5NDMyN1oXDTI1MDYwNTE3NDMyN1owODELMAkGA1UEBhMCU0UxEjAQBgNVBAoTCUVTVC1Db0FQUzEVMBMGA1UEAxMMRVNULUNvQVBTIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzeSzSReaFHPk6166dCW2aafaKIiOlCM4ZP3VxfLmmj2Q8q8LAYQh7xbyIEnq8p+bo3W3YMsgNz8GwDtepqD8SqMzMDEwDwYDVR0TAQH/BAUwAwEB/zARBgNVHQ4ECgQIRi0+wat3BfIwCwYDVR0PBAQDAgEGMAoGCCqGSM49BAMCA0cAMEQCICO9hiAzg7+9vBojLbx44aN4FqsaNcvscxoB51dV729HAiBACvbJXMCz6zt7a4cENvzB9HiZoSpqbwSYUEZdkGIfkA=="



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


/*
#define INITIAL_TRUSTSTORE \
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
 "-----END CERTIFICATE-----\r\n" \
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
*/

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

#endif

/*
 * Good to have: \n --> \\r\\n"\t \\\n "
 */

/*
 * Standalone specific settings
 */
#define PLATFORM_HAS_TIME 1
#define HAVE_RANDOM       1
typedef uint32_t ret_code_t;
/*
 * Standalone logging
 */
#define LOG_CONF_LEVEL_EST_CLIENT         LOG_LEVEL_DBG
#define TRUSTSTORE_PARSE_BUFFER_SIZE 4096


#endif
