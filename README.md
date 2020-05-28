# SecureCare

## Project Structure
- `boot` contains the bootloader for the DFU client.
- `rs` contains the application code for the ACE resource server and DFU client.

## Build and Run
1. Run `make mbr` from the `boot` directory to flash the master boot record.
2. Run `make flash` from the `boot` directory to flash the bootloader.
3. Run `make flash` from the `rs` directory to flash the application code.

## Toolchain Installation
This code has been built and tested on an nRF52840 using the [nRF5 SDK for Thread v4.1.0](https://www.nordicsemi.com/Software-and-tools/Software/nRF5-SDK-for-Thread-and-Zigbee/Download). Create an environment variable called `$NRF5_SDK` pointing to the SDK directory before running `make`. The SDK expects to find a copy of the [Arm GCC Embedded Toolchain v7-2018-q2-update](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) in the `/usr/local` directory. 
