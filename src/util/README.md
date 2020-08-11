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

SUIT version		1
Component count		1
Sequence number		0

Component details:
(0) Remote URI		coaps://[::1]/firmware.hex
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
