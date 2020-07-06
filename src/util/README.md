## SUIT Command Line Interface
The `suit-cli` tool is catered specifically to a secure download/install/reboot use case. It does not generate any other instruction sequences at this time. To generate a new SUIT manifest:
```
./build/suit-cli -k keys/priv.pem -n 0 -u coaps://[::1]/firmware > manifest.cbor < firmware.exe
```

To verify the contents of a SUIT manifest:
```
./build/suit-cli -k keys/pub.pem -p < manifest.cbor
```

This should produce output similar to the following:
```
Signature OK!

SUIT version		1
Component count		1
Sequence number		0

Component details:
(0) Remote URI		coaps://[::1]/firmware
(0) Class ID		1492af1425695e48bf429b2d51f2ab45
(0) Vendor ID		fa6b4a53d5ad5fdfbe9de663e4d41ffe
(0) Image digest	e9a0f5f4c77a4d4c2ee442ff2ef73b60fceee988dd83232dff5479352064e27d
(0) Image size		1337 [B]
```

## CoAPs File Server
This directory contains a modified version of the example server from the `libcoap` source code, which will host all files (non-recursively) in a specified directory as CoAP GET resources. Use the `-d` flag to specify that directory. Refer to the help text for a complete list of options, including certificate and key configuration.
