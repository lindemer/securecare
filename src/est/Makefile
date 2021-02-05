UTIL  := $(CURDIR)/util
#ECC  := $(CURDIR)/../other-ecc
CBOR  := $(CURDIR)/../../lib/NanoCBOR
DONNA := $(CURDIR)/../../lib/curve25519-donna
BUILD := $(CURDIR)/build

CC := gcc

_OBJ += est-client.o
#_OBJ += ecdh_example.o	
_OBJ += client.o est.o est-asn1.o est-base64.o est-cms.o est-oid.o est-pkcs10.o est-x509.o  
_OBJ += crypto-wrapper.o
#other-ecc.o ecc-sha1.o secp256r1.o sha224-256.o
_OBJ += memb.o
_OBJ += encoder.o decoder.o
_OBJ += curve25519-donna.o


ifeq ($(UC),1)
${info Compiling with CBOR}
CFLAGS += -DUSE_CBOR_ENCODING=1
_OBJ += xiot.o
else
${info Compiling with standard format}
endif

#Standalone flags:
CFLAGS += -DSTANDALONE_VERSION=1

#Test with Nexus flag:
ifeq ($(N),1)
${info Compiling for use with Nexus server}
CFLAGS += -DEST_WITH_NEXUS=1
else
${info Compiling for use with local EST server}
endif

#CFLAGS += -DPLATFORM_HAS_TIME=1 #in project-conf

#management
OBJ = $(patsubst %,$(BUILD)/%,$(_OBJ))

#DEPS = $(CURDIR)/client.h

CFLAGS += -Wall -Werror -g3
CBOR_FLAGS += -DNANOCBOR_BYTEORDER_HEADER=\"nanocbor/nanocbor.h\"
CBOR_FLAGS += -DNANOCBOR_HTOBE32_FUNC=__builtin_bswap32
CBOR_FLAGS += -DNANOCBOR_HTOBE64_FUNC=__builtin_bswap64
CBOR_FLAGS += -DNANOCBOR_BE64TOH_FUNC=__builtin_bswap64
INCLUDES += -I$(CBOR)/include/
#INCLUDES += -I$(COSE)
#INCLUDES += -I$(EST)
INCLUDES += -I$(UTIL)
INCLUDES += -I.
#CFLAGS += -Wall -Werror -g $(INCLUDES)
CFLAGS += -w -g $(INCLUDES)
CFLAGS += -DJACOBIAN_COORDINATES=1 -DSECP256R1=1

LIBS = -lmbedtls -lmbedcrypto -lmbedx509 -lcoap-2-openssl

default: mkdir est-client

mkdir:
	@mkdir -p $(BUILD)

all: $(OBJ)

$(BUILD)/memb.o: $(UTIL)/memb.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 


ifeq ($(UC),1)
$(BUILD)/xiot.o: $(UTIL)/xiot.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 
endif


$(BUILD)/encoder.o: $(CBOR)/src/encoder.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

$(BUILD)/decoder.o: $(CBOR)/src/decoder.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

$(BUILD)/curve25519-donna.o: $(DONNA)/curve25519-donna.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

#$(BUILD)/log.o: $(UTIL)/log.c
#	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 


$(BUILD)/%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
	
est-client: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

	
.PHONY: clean

clean:
	@rm -rf $(BUILD)	

