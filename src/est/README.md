A demo EST client, performing both the cacerts and simple enroll operations with a suitable enrollment server.

make, and ./est-client to run

History, newest on top

2020-07-29
Refactored to use mbedtls only for EST operations. All mbedtls operations happen in mbedtls-wrapper. +removal of hardcoded CA certificate

2020-07-20
Current version the EST operations are done using the ecc library from Contiki to generate and check signatures
