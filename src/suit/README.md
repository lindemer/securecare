## Usage
`./build/suit [-hknpu] > [output file] < [input file]`

- `-h` displays this text
- `-k` [key file]
- `-n` [sequence number]
- `-p` parses a manifest from stdin and decodes it
- `-u` [remote firmware URI]

## Examples
`./build/suit -k keys/priv.pem -n 0 -u coaps://[::1]/firmware > manifest.cbor < firmware.exe`
`./build/suit -k keys/pub.pem -p < manifest.cbor`
