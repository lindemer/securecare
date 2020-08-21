/*
 * Copyright (c) 2015, Swedish Institute of Computer Science.
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
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *          OIDs that are used in CMS, PKCS #10, X.509
 * \author
 *         Rúnar Már Magnússon  <rmma@kth.se>
 *         Tómas Þór Helgason   <helgas@kth.se>
 */

#ifndef EST_OID_H
#define EST_OID_H

#include "inttypes.h"
#include "string.h"

#define OID_DBG(...)


/**
 *  From RFC 5652 - Cryptographic Message Syntax
 */
/* Content Type Object Identifiers */
#define OID_ID_CT_CONTENT_INFO "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x06" /* id-ct-contentInfo: 1.2.840.113549.1.9.16.1.6 */
#define OID_ID_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" /* id-data: 1.2.840.113549.1.7.1 */
#define OID_ID_SIGNED_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" /* id-signedData: 1.2.840.113549.1.7.2 */
#define OID_ID_ENVELOPED_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" /* id-envelopedData: 1.2.840.113549.1.7.3 */
#define OID_ID_DIGEST_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" /* id-digestedData: 1.2.840.113549.1.7.5 */
#define OID_ID_ENCRYPTED_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" /* id-encryptedData: 1.2.840.113549.1.7.6 */
#define OID_ID_CT_AUTH_DATA "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x02" /* id-ct-authData: 1.2.840.113549.1.9.16.1.2 */

/* Attribute Object Identifiers */
#define OID_ID_CONTENT_TYPE "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03" /* id-contentType: 1.2.840.113549.1.9.3 */
#define OID_ID_MESSAGE_DIGEST "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04" /* id-messageDigest: 1.2.840.113549.1.9.4 */
#define OID_ID_SIGNING_TIME "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05" /* id-signingTime: 1.2.840.113549.1.9.5 */
#define OID_ID_COUNTER_SIGNATURE "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x06" /* id-countersignature: 1.2.840.113549.1.9.6 */

/**
 *  From RFC 5280 - Internet X.509 Public Key Infrastructure Certificate
 */
/* Explicit */
/* PKIX arcs */
#define OID_ID_PKIX "\x2B\x06\x01\x05\x05\x07" /* id-pkix: 1.3.6.1.5.5.7 */
#define OID_ID_PE "\x2B\x06\x01\x05\x05\x07\x01" /* id-pe: 1.3.6.1.5.5.7.1 */
#define OID_ID_QT "\x2B\x06\x01\x05\x05\x07\x02" /* id-qt: 1.3.6.1.5.5.7.2 */
#define OID_ID_KP "\x2B\x06\x01\x05\x05\x07\x03" /* id-kp: 1.3.6.1.5.5.7.3 */
#define OID_ID_AD "\x2B\x06\x01\x05\x05\x07\x30" /* id-ad: 1.3.6.1.5.5.7.48 */

/* policyQualifierIds */
#define OID_ID_QT_CPS "\x2B\x06\x01\x05\x05\x07\x02\x01" /* id-qt-cps: 1.3.6.1.5.5.7.2.1 */
#define OID_ID_QT_UNOTICE "\x2B\x06\x01\x05\x05\x07\x02\x02" /* id-qt-unotice: 1.3.6.1.5.5.7.2.2 */

/* Access descriptor definitions */
#define OID_ID_AD_OCSP "\x2B\x06\x01\x05\x05\x07\x30\x01" /* id-ad-ocsp: 1.3.6.1.5.5.7.48.1 */
#define OID_ID_AD_CA_ISSUER "\x2B\x06\x01\x05\x05\x07\x30\x02" /* id-ad-ocsp: 1.3.6.1.5.5.7.48.2 */
#define OID_ID_AD_TIME_STAMPING "\x2B\x06\x01\x05\x05\x07\x30\x03" /* id-ad-ocsp: 1.3.6.1.5.5.7.48.3 */
#define OID_ID_AD_CA_REPOSITORY "\x2B\x06\x01\x05\x05\x07\x30\x05" /* id-ad-ocsp: 1.3.6.1.5.5.7.48.5 */

/* Arc for standard naming attributes */
#define OID_ID_AT "\x55\x04" /* id-at: 2.5.4 */

/* Naming attributes of type X520name */
#define OID_ID_AT_NAME "\x55\x04\x29" /* id-at-name: 2.5.4.41 */
#define OID_ID_AT_SURNAME "\x55\x04\x04" /* id-at-surname: 2.5.4.4 */
#define OID_ID_AT_GIVEN_NAME "\x55\x04\x2A" /* id-at-givenName: 2.5.4.42 */
#define OID_ID_AT_INITIALS "\x55\x04\x2B" /* id-at-initials: 2.5.4.43 */
#define OID_ID_AT_GENERATION_QUALIFIER "\x55\x04\x2C" /* id-at-generationQualifier: 2.5.4.44 */

/* Naming attributes of type X520CommonName */
#define OID_ID_AT_COMMON_NAME "\x55\x04\x03" /* id-at-commonName: 2.5.4.3 */

/* Naming attributes of type X520LocalityName */
#define OID_ID_AT_LOCALITY_NAME "\x55\x04\x07" /* id-at-localityName: 2.5.4.7 */

/* Naming attributes of type X520StateOrProvinceName */
#define OID_ID_AT_STATE_OR_PROVINCE_NAME "\x55\x04\x08" /* id-at-stateOrProvinceName: 2.5.4.8 */

/* Naming attributes of type X520OrganizationName */
#define OID_ID_AT_ORGANIZATION_NAME "\x55\x04\x0A" /* id-at-organizationName: 2.5.4.10 */

/* Naming attributes of type X520OrganizationalUnitName */
#define OID_ID_AT_ORGANIZATIONAL_UNIT_NAME "\x55\x04\x0B" /* id-at-organizationalUnitName: 2.5.4.11 */

/* Naming attributes of type X520Title */
#define OID_ID_AT_TITLE "\x55\x04\x0C" /* id-at-title: 2.5.4.12 */

/* Naming attributes of type X520dnQualifier */
#define OID_ID_AT_DN_QUALIFIER "\x55\x04\x2E" /* id-at-title: 2.5.4.46 */

/* Naming attributes of type X520countryName */
#define OID_ID_AT_COUNTRY_NAME "\x55\x04\x06" /* id-at-countryName: 2.5.4.6 */

/* Naming attributes of type X520SerialNumber */
#define OID_ID_AT_SERIAL_NAME "\x55\x04\x05" /* id-at-serialNumber: 2.5.4.5 */

/* Naming attributes of type X520Pseudonym */
#define OID_ID_AT_PSEUDONYM "\x55\x04\x41" /* id-at-pseudonym: 2.5.4.65 */

/* Naming attributes of type DomainComponent */
#define OID_ID_DOMAIN_COMPONENT "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19" /* id-at-serialNumber: 0.9.2342.19200300.100.1.25 */

/* Legacy attributes */
#define OID_PKCS_9 "\x2A\x86\x48\x86\xF7\x0D\x01\x09" /* pkcs_9: 1.2.840.113549.1.9 */

/* Naming attributes of type X520SerialNumber */
#define OID_ID_EMAIL_ADDRESS "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01" /* id-emailAddress: 1.2.840.113549.1.9.1 */

/* Implicit */
/* ISO arc for standard certificate and CRL extensions */
#define OID_ID_CE "\x55\x1D" /* id-ce: 2.5.29 */
#define OID_ID_CE_AUTHORITY_KEY_IDENTIFIER "\x55\x1D\x23" /* id-ce-authorityKeyIdentifier: 2.5.29.35 */
#define OID_ID_CE_SUBJECT_KEY_IDENTIFIER "\x55\x1D\x0E" /* id-ce-subjectKeyIdentifier: 2.5.29.14 */
#define OID_ID_CE_KEY_USAGE "\x55\x1D\x0F" /* id-ce-keyUsage: 2.5.29.15 */
#define OID_ID_CE_PRIVATE_KEY_USAGE_PERIOD "\x55\x1D\x10" /* id-ce-privateKeyUsagePeriod: 2.5.29.16 */
#define OID_ID_CE_CERTIFICATE_POLICIES "\x55\x1D\x20" /* id-ce-certificatePolicies: 2.5.29.32 */
#define OID_ANY_POLICY "\x55\x1D\x20\x00" /* anyPolicy: 2.5.29.32.0 */
#define OID_ID_CE_POLICY_MAPPINGS "\x55\x1D\x21" /* id-ce-policyMappings: 2.5.29.33 */
#define OID_ID_CE_SUBJECT_ALT_NAME "\x55\x1D\x11" /* id-ce-subjectAltName: 2.5.29.17 */
#define OID_ID_CE_ISSUER_ALT_NAME "\x55\x1D\x12" /* id-ce-issuerAltName: 2.5.29.18 */
#define OID_ID_CE_SUBJECT_DIR_ATTRIBUTES "\x55\x1D\x09" /* id-ce-subjectDirectoryAttributes: 2.5.29.9 */
#define OID_ID_CE_BASIC_CONSTRAINTS "\x55\x1D\x13" /* id-ce-basicConstraints: 2.5.29.19 */
#define OID_ID_CE_NAME_CONSTRAINTS "\x55\x1D\x1E" /* id-ce-basicConstraints: 2.5.29.30 */
#define OID_ID_CE_POLICY_CONSTRAINTS "\x55\x1D\x24" /* id-ce-policyConstraints: 2.5.29.36 */
#define OID_ID_CE_CRL_DISTRIBUTION_POINTS "\x55\x1D\x1F" /* id-ce-cRLDistributionPoints: 2.5.29.31 */
#define OID_ID_CE_EXT_KEY_USAGE "\x55\x1D\x25" /* id-ce-extKeyUsage: 2.5.29.37 */
#define OID_ANY_EXTENDED_KEY_USAGE "\x55\x1D\x25\x00" /* anyExtendedKeyUsage: 2.5.29.37.0 */

/* Extended key purpose */
#define OID_ID_KP_SERVER_AUTH "\x2B\x06\x01\x05\x05\x07\x03\x01" /* id-kp-serverAuth: 1.3.6.1.5.5.7.3.1 */
#define OID_ID_KP_CLIENT_AUTH "\x2B\x06\x01\x05\x05\x07\x03\x02" /* id-kp-clientAuth: 1.3.6.1.5.5.7.3.2 */
#define OID_ID_KP_CODE_SIGNING "\x2B\x06\x01\x05\x05\x07\x03\x03" /* id-kp-codeSigning: 1.3.6.1.5.5.7.3.3 */
#define OID_ID_KP_EMAIL_PROTECTION "\x2B\x06\x01\x05\x05\x07\x03\x04" /* id-kp-emailProtection: 1.3.6.1.5.5.7.3.4 */
#define OID_ID_KP_TIME_STAMPING "\x2B\x06\x01\x05\x05\x07\x03\x08" /* id-kp-timeStamping: 1.3.6.1.5.5.7.3.8 */
#define OID_ID_KP_OCSP_SIGNING "\x2B\x06\x01\x05\x05\x07\x03\x09" /* id-kp-OCSPSigning: 1.3.6.1.5.5.7.3.9 */

/* Inhibit any policy */
#define OID_ID_CE_INHIBIT_ANY_POLICY "\x55\x1D\x36" /* id-ce-inhibitAnyPolicy: 2.5.29.54 */

/* Freshest */
#define OID_ID_CE_FRESHEST_CRL "\x55\x1D\x2E" /* id-ce-freshestCRL: 2.5.29.46 */

/* Authority info access */
#define OID_ID_PE_AUTHORITY_INFO_ACCESS "\x2B\x06\x01\x05\x05\x07\x01\x01" /* id-pe-authorityInfoAccess : 1.3.6.1.5.5.7.1.1 */

/* Subject info access */
#define OID_ID_PE_SUBJECT_INFO_ACCESS "\x2B\x06\x01\x05\x05\x07\x01\x0B" /* id-pe-subjectInfoAccess : 1.3.6.1.5.5.7.1.11 */

/* CRL number extension */
#define OID_ID_CE_CRL_NUMBER "\x55\x1D\x14" /* id-ce-cRLNumber : 2.5.29.20 */

/* Issuing distribution point extension */
#define OID_ID_CE_ISSUING_DISTRIBUTION_POINT "\x55\x1D\x1C" /* id-ce-issuingDistributionPoint : 2.5.29.28 */
#define OID_ID_CE_DELTA_CRL_INDICATOR "\x55\x1D\x1B" /* id-ce-deltaCRLIndicator : 2.5.29.27 */

/* Reason code extension */
#define OID_ID_CE_CRL_REASONS "\x55\x1D\x15" /* id-ce-deltaCRLReasons: 2.5.29.21 */

/* Certificate issuer CRL entry extension */
#define OID_ID_CE_CERTIFICATE_ISSUER "\x55\x1D\x1D" /* id-ce-certificateIssuer : 2.5.29.29 */

/* Hold instruction extension*/
#define OID_ID_CE_HOLD_INSTRUCTION_CODE "\x55\x1D\x17" /* id-ce-holdInstructionCode : 2.5.29.23 */

/**
 *  Other
 */
/* ECC Public Key*/
#define OID_ID_EC_PUBLIC_KEY "\x2A\x86\x48\xCE\x3D\x02\x01" /* id-ecPublicKey: 1.2.840.10045.2.1 */

/* ECDSA algorithm Identifiers */
#define OID_ALGORITHM_ECDSA_WITH_SHA224 "\x2A\x86\x48\xCE\x3D\x04\x03\x01" /* 1.2.840.10045.4.3.1 */
#define OID_ALGORITHM_ECDSA_WITH_SHA256 "\x2A\x86\x48\xCE\x3D\x04\x03\x02" /* 1.2.840.10045.4.3.2 */
#define OID_ALGORITHM_ECDSA_WITH_SHA384 "\x2A\x86\x48\xCE\x3D\x04\x03\x03" /* 1.2.840.10045.4.3.3 */
#define OID_ALGORITHM_ECDSA_WITH_SHA512 "\x2A\x86\x48\xCE\x3D\x04\x03\x04" /* 1.2.840.10045.4.3.4 */

/* ECC Curve Names OIDs*/
#define OID_CURVE_NAME_SECP192R1 "\x2A\x86\x48\xCE\x3D\x03\x01\x01" /* 1.2.840.10045.3.1.1 */
#define OID_CURVE_NAME_SECP256R1 "\x2A\x86\x48\xCE\x3D\x03\x01\x07" /* 1.2.840.10045.3.1.7 */
#define OID_CURVE_NAME_SECP384R1 "\x2B\x81\x04\x00\x22"             /* 1.3.132.0.34 */
#define OID_CURVE_NAME_SECP521R1 "\x2B\x81\x04\x00\x23"             /* 1.3.132.0.35 */

/* Macro to get the length of a stored OID*/
#define OID_LENGTH(oid) (strlen(oid))

/**
 * Compares an OID from oid_buf of length oid_len with a defined oid
 * @param str_oid the known OID (e.g. OID_CURVE_NAME_SCEP192R1
 * @param oid_buf the buffer that stores the oid to compare with
 * @param oid_len the length of the oid
 * @return 0 if they are the same -1 otherwise
 */
int oid_cmp(char *str_oid, uint8_t *oid_buf, uint16_t oid_len);

#endif /* EST_OID_H */

