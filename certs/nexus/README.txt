
[Information]

 This package contains required PKI files to run EST over CoAP
 on a public CM hosted server running CM 8.3.0.

 Addresses:
  - IPv4: nexuscm-integration.westeurope.cloudapp.azure.com (51.124.21.81)
  - IPv6: nexuscm-integration-ipv6.westeurope.cloudapp.azure.com (2603:1020:203:3::2b)
  
 This endpoints are:
  - cacerts:        /.well-known/est/coap/crts
  - simpleenroll:   /.well-known/est/coap/sen
  - simplereenroll: /.well-known/est/coap/sren
  - serverkeygen:   /.well-known/est/coap/skg
  
 Note that the endpoints also can be found with the discovery option.

 Ports:
  - 5683 (unsecure)
  - 5684 (DTLS)

 The "Device Factory PKI" folder contains CA certificates and PKCS12 key store for the factory device
 that will request the CoAP service. You would need to import the "EST-CoAPS-device-factory.p12"
 key store in to your device. The other certificates listed here are probably not needed by the device.

 - PKCS12 PIN: abcd1234

 The "EST-CoAPS PKI CAs" folder contains the CoAP PKI CA chain that will issue the EU certificates
 over CoAP. The same issuing CA has issued the DTLS certificate used by the CoAPS, which means that
 the root CA certificate "EST-CoAPS_ca.cer" should be imported for trust into your factory device
 when using CoAP over DTLS.

 The cacerts endpoint will return the root CA "EST-CoAPS_ca.cer" and the issuing CA "EST-CoAPS_issuing_ca.cer".
 The enrollment endpoints will return a certificate issued by "EST-CoAPS_issuing_ca.cer".
 