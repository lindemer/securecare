# SecureCare
This is an experimental implementation of the [SUIT protocol](https://datatracker.ietf.org/wg/suit/about/) for the SIP-IoT SecureCare project at RISE Research Institutes of Sweden targeting the Nordic Semiconductor nRF52840 DK. The project includes (partial) implementations of the following IETF standards and drafts:
- [RFC 8152](https://tools.ietf.org/html/rfc8152) CBOR Object Signing and Encryption (COSE)
- [RFC 8392](https://tools.ietf.org/html/rfc8392/) CBOR Web Token
- [RFC 8747](https://tools.ietf.org/html/rfc8747) Proof-of-Possession Key Semantics for CBOR Web Tokens (CWTs)
- [Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-ace-oauth-authz/) Authorization and Access Control for Constrained Environments (ACE)
- [Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) CBOR SUIT Manifest

![alt text](https://github.com/lindemer/securecare/blob/master/securecare.png "SecureCare logo")

## Usage
The nRF52840 node is flashed with the default Thread credentials included with the [OpenThread border router](https://github.com/openthread/ot-br-posix) and should connect automatically to the network. `LED1` indicates the Thread connection status: off for detached, blink for connecting and on for connected. The node has a CoAP PUT endpoint at `/s` for receiving SUIT manifests. 

The [mesh-local EID](https://openthread.io/guides/thread-primer/ipv6-addressing) IPv6 address of the board can be discovered by connecting a serial port communication program (e.g., `sudo minicom -D /dev/ttyACM0 -b 115200`) and running `ipaddr` from the OpenThread CLI. Alternatively, the link-local IPv6 address can discovered by pinging `ff02::1%wpan0` from the border router. The OpenThread border router is pre-configured with a NAT64 interface. Run `dns resolve ipv4.google.com fdaa:bb:1::2` from the OpenThread CLI on the node to check Internet connectivity.

## Project Structure
- `keys` key pair for SUIT manifest signing and verification
- `lib` external libraries 
- `src/boot` bootloader for the SUIT DFU client
- `src/app` application code for the SUIT DFU client
- `src/suit` SUIT manifest parser and encoder
- `src/cose` COSE parser and encoder
- `src/ace` ACE client and authorization server

## Build and Run
1. Run `make keys` from the `src/boot` directory to generate a key pair.
2. Run `make mbr` from the `src/boot` directory to flash the master boot record to the nRF52840.
3. Run `make flash` from the `src/boot` directory to flash the bootloader to the nRF52840.
4. Run `make flash` from the `src/app` directory to flash the application code to the nRF52840.
5. Run `make` from the `src/suit` directory to compile the SUIT CLI encoder.
6. Run `make client` from the `src/ace` directory to compile the ACE client.
7. Run `make server` from the `src/ace` directory to compile the ACE authorization server.

## Toolchain Installation
This code has been built and tested on an nRF52840 DK using the [nRF5 SDK for Thread v4.1.0](https://www.nordicsemi.com/Software-and-tools/Software/nRF5-SDK-for-Thread-and-Zigbee/Download). Create an environment variable called `$NRF5_SDK` pointing to the SDK directory before running `make`. The SDK expects to find a copy of the [Arm GCC Embedded Toolchain v7-2018-q2-update](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) in the `/usr/local` directory.

The SUIT CLI encoder depends on [mbedTLS](https://github.com/ARMmbed/mbedtls) which can be installed with the command `sudo make install`. 
