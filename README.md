# SecureCare
This is an experimental implementation of the [SUIT protocol](https://datatracker.ietf.org/wg/suit/about/) for the SIP-IoT SecureCare project at [RISE Research Institutes of Sweden](https://www.ri.se/) targeting the Nordic Semiconductor nRF52840. The repository contains partial implementations of the following IETF standards and drafts:
- [RFC 8152](https://tools.ietf.org/html/rfc8152) CBOR Object Signing and Encryption (COSE)
- [RFC 8392](https://tools.ietf.org/html/rfc8392/) CBOR Web Token (CWT)
- [RFC 8747](https://tools.ietf.org/html/rfc8747) Proof-of-Possession Key Semantics for CWTs
- [Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-ace-oauth-authz/) Authorization and Access Control for Constrained Environments (ACE)
- [Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) CBOR SUIT Manifest

![SecureCare logo](https://github.com/lindemer/securecare/blob/master/securecare.png "SecureCare logo")

## Usage
The nRF52840 node is flashed with the default Thread credentials included with the [OpenThread border router](https://github.com/openthread/ot-br-posix) and should connect automatically to the network. `LED1` indicates the Thread connection status: off for detached, blink for connecting and on for connected. The node has a CoAP PUT endpoint at `/s` for receiving SUIT manifests. 

The [mesh-local EID](https://openthread.io/guides/thread-primer/ipv6-addressing) IPv6 address of the board can be discovered by connecting a serial port communication program (e.g., `sudo minicom -D /dev/ttyACM0 -b 115200`) and running `ipaddr` from the OpenThread CLI. Alternatively, the link-local IPv6 address can discovered by pinging `ff02::1%wpan0` from the border router. The OpenThread border router is pre-configured with a NAT64 interface. Run `dns resolve ipv4.google.com fdaa:bb:1::2` from the OpenThread CLI on the node to check Internet connectivity.

## Project Structure
- `key` keys and certificates
- `lib` external libraries 
- `src/ace` ACE client and authorization server
- `src/cose` COSE, CWT and SUIT parser/encoder sources
- `src/demo` example code for the nRF52840 SoC
- `src/est` EST-CoAPs sources
- `src/util` command line utilities

## Build Components
1. Run `make` from `key` to generate keys. (This will overwrite existing keys).
2. Run `make` from `src/demo` to flash the example code to an nRF52840 SoC.
3. Run `make` from `src/util` to compile CLI utilities.
4. Run `make` from `src/ace` to compile the ACE client and authorization server.

## Toolchain Installation
This code has been built and tested on an nRF52840 DK using the [nRF5 SDK for Thread v4.1.0](https://www.nordicsemi.com/Software-and-tools/Software/nRF5-SDK-for-Thread-and-Zigbee/Download). Create an environment variable called `$NRF5_SDK` pointing to the SDK directory before running `make`. The SDK expects to find a copy of the [Arm GCC Embedded Toolchain v7-2018-q2-update](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) in the `/usr/local` directory.

The Linux-native components of this project depend on a local installation of [libcoap](https://github.com/obgm/libcoap) and [mbedTLS](https://github.com/ARMmbed/mbedtls), both of which can be found in `lib`. 
