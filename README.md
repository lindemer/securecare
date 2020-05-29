# SecureCare
This is an experimental implementation of the [SUIT protocol](https://datatracker.ietf.org/wg/suit/about/) for the SIP-IoT SecureCare project at RISE Research Institutes of Sweden targeting the Nordic Semiconductor nRF52840 DK.

## Usage
The flashed nRF52840 device is pre-programmed with the default Thread network credentials included with the [OpenThread border router](https://github.com/openthread/ot-br-posix) **for development purposes only**, and should connect automatically. `LED1` indicates the Thread connection status: off for detached, blink for connecting and on for connected. The device has a CoAP PUT endpoint at `/s` for sending SUIT manifests. The [mesh-local EID](https://openthread.io/guides/thread-primer/ipv6-addressing) IPv6 address of the board can be discovered by connecting a serial port communication program (e.g., `sudo minicom -D /dev/ttyACM0 -b 115200`) and running `ipaddr` from the OpenThread CLI. Alternatively, the link-local IPv6 address can discovered by pinging `ff02::1%wpan0` from the border router.

## Project Structure
- `keys` key pair for SUIT manifest signing and verification
- `src/boot` bootloader for the SUIT DFU client
- `src/app` application code for the SUIT DFU client
- `src/suit` SUIT manifest parser and encoder
- `src/cose` COSE parser and encoder

## Build and Run
1. Run `make keys` from the `src/boot` directory to generate a key pair.
2. Run `make mbr` from the `src/boot` directory to flash the master boot record.
3. Run `make flash` from the `src/boot` directory to flash the bootloader.
4. Run `make flash` from the `src/app` directory to flash the application code.

## Toolchain Installation
This code has been built and tested on an nRF52840 DK using the [nRF5 SDK for Thread v4.1.0](https://www.nordicsemi.com/Software-and-tools/Software/nRF5-SDK-for-Thread-and-Zigbee/Download). Create an environment variable called `$NRF5_SDK` pointing to the SDK directory before running `make`. The SDK expects to find a copy of the [Arm GCC Embedded Toolchain v7-2018-q2-update](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) in the `/usr/local` directory. 
