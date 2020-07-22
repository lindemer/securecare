UTIL  := $(CURDIR)/../util
ECC  := $(CURDIR)/../other-ecc
#CBOR  := $(CURDIR)/../../lib/NanoCBOR
BUILD := $(CURDIR)/build

CC := gcc
	
_OBJ = est-client.o client.o est.o est-asn1.o est-base64.o est-cms.o est-oid.o est-pkcs10.o est-x509.o handle-dtls-settings.o 
_OBJ += other-ecc.o bigint.o ecc-sha1.o secp256r1.o sha224-256.o
_OBJ += memb.o

OBJ = $(patsubst %,$(BUILD)/%,$(_OBJ))

#DEPS = $(CURDIR)/client.h

CFLAGS += -Wall -Werror -g
CBOR_FLAGS += -DNANOCBOR_BYTEORDER_HEADER=\"nanocbor/nanocbor.h\"
CBOR_FLAGS += -DNANOCBOR_HTOBE32_FUNC=__builtin_bswap32
CBOR_FLAGS += -DNANOCBOR_HTOBE64_FUNC=__builtin_bswap64
CBOR_FLAGS += -DNANOCBOR_BE64TOH_FUNC=__builtin_bswap64
#INCLUDES += -I$(CBOR)/include
#INCLUDES += -I$(COSE)
#INCLUDES += -I$(EST)
INCLUDES += -I$(UTIL)
INCLUDES += -I$(ECC)
INCLUDES += -I.
CFLAGS += -Wall -Werror -g $(INCLUDES)
CFLAGS += -DJACOBIAN_COORDINATES=1 -DSECP256R1=1

LIBS = -lmbedtls -lmbedcrypto -lmbedx509 -lcoap-2-openssl

default: mkdir est-client

mkdir:
	@mkdir -p $(BUILD)

all: $(OBJ)

$(BUILD)/bigint.o: $(ECC)/bigint.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

$(BUILD)/ecc-sha1.o: $(ECC)/ecc-sha1.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

$(BUILD)/sha224-256.o: $(ECC)/sha224-256.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

$(BUILD)/secp256r1.o: $(ECC)/secp256r1.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

$(BUILD)/other-ecc.o: $(ECC)/other-ecc.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) 

$(BUILD)/memb.o: $(UTIL)/memb.c
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

