## SUIT Command Line Interface
The `suit-cli` tool is catered specifically to a secure download/install/reboot use case. It does not generate any other instruction sequences at this time. To generate a new SUIT manifest:
```
./build/suit-cli -k keys/priv.pem -n 0 -u coaps://[fd00::1]/app.bin -i app.bin > manifest.cbor
```

To verify the contents of a SUIT manifest:
```
./build/suit-cli -k keys/pub.pem -v < manifest.cbor
```

This should produce output similar to the following:
```
Signature OK!

SUIT version      1
Component count   1
Sequence number   0

Component details:
(0) Remote URI		coaps://[::1]/app.bin
(0) Class ID		1492af1425695e48bf429b2d51f2ab45
(0) Vendor ID		fa6b4a53d5ad5fdfbe9de663e4d41ffe
(0) Image digest	e9a0f5f4c77a4d4c2ee442ff2ef73b60fceee988dd83232dff5479352064e27d
(0) Image size		1994 [B]
```

## CoAPs SUIT Demo Server
The `demo-server` tool can be used to test the SUIT DFU protocol. This is, in essence, a file server, which will host all files in the current directory as CoAP GET resources. (Another directory can also be specified with the `-d` flag.) The SUIT DFU protocol in this demonstration consists of three steps:

  1. The client requests the size and CRC32 value of the SUIT manifest on the demo server using the `?meta` URI query option.
  2. The client downloads the manifest using the `block2` option. (The data retrieved in step 1 are used to confirm that the download is complete.
  3. The client verifies the SUIT manifest and parses the size and remote URI of the specified firmware image. These values are used to initiate the firmware download using another `block2` request.
  
The simplest way to run this example is to generate a SUIT manifest with the `suit-cli` tool which specifies the demo server's IPv6 address as the remote host of the firmware image. This image can then be hosted as a `GET` resource on the same server bu placing it in the designated directory.

## Example Usage
This example uses the OpenThread border router as the demo server machine.

  1. Run `make` from the `src/demo` directory to flash the bootloader, master boot record and application code to a connected nRF52840 device. The application binary will be placed in `src/demo/app/build`.
  2. Copy `src/demo/app/build/app.bin` to the `src/util` directory (on the border router) to host it using the demo server.
  3. Run `sudo ip addr add fd00::1 dev eth0` on the border router to give the demo server a routable IPv6 address from the Thread network.
  4. Run `./build/suit-cli -k ../../key/priv.pem -n 0 -u coap://[fd00::1]/app.bin -i app.bin > manifest.cbor` from the `src/util` directory to generate a manifest for the application binary.
  5. Start the Thread network from the browser-based GUI on the border router using the default credentials.
  6. Run `./build/demo-server` to start the server.
  7. (Optional) Run `JLinkRTTLogger` on the machine connected to the nRF52840 to view logs in real time. Use the following settings: device name `NRF52840_XXAA`, target interface `SWD`, channel `0`, output file `/dev/stdout`.
  8. Reset the device to initiate the DFU process.

*For CoAP(s)* set the firmware URI to `coaps://[fd00::1]/app.bin` in step 4 and run `./build/demo-server -k secret` in step 6 to run the demo server with the hard-coded PSK.
