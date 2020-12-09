SUIT  := $(CURDIR)/../cose
COSE  := $(CURDIR)/../cose
CBOR  := $(CURDIR)/../../lib/NanoCBOR
BUILD := $(CURDIR)/build

CC := gcc

SRCS = \
    $(CBOR)/src/encoder.c \
    $(CBOR)/src/decoder.c \
    $(COSE)/cose.c \
    $(SUIT)/suit.c \
    $(CURDIR)/suit-cli.c \

OBJS ?= \
    $(BUILD)/encoder.o \
    $(BUILD)/decoder.o \
    $(BUILD)/cose.o \
    $(BUILD)/suit.o \
    $(BUILD)/suit-cli.o \

CFLAGS += -Wall -Werror -g
CBOR_FLAGS += -DNANOCBOR_BYTEORDER_HEADER=\"nanocbor/nanocbor.h\"
CBOR_FLAGS += -DNANOCBOR_HTOBE32_FUNC=__builtin_bswap32
CBOR_FLAGS += -DNANOCBOR_HTOBE64_FUNC=__builtin_bswap64
CBOR_FLAGS += -DNANOCBOR_BE64TOH_FUNC=__builtin_bswap64
INCLUDES += -I$(CBOR)/include
INCLUDES += -I$(COSE)
INCLUDES += -I.
LIBS = -lmbedtls -lmbedcrypto -lcoap-2-openssl

default: mkdir suit-cli demo-server

mkdir:
	@mkdir -p $(BUILD)

$(BUILD)/encoder.o: $(CBOR)/src/encoder.c
	$(CC) -c -o $@ $< $(CFLAGS) $(CBOR_FLAGS) $(INCLUDES)

$(BUILD)/decoder.o: $(CBOR)/src/decoder.c
	$(CC) -c -o $@ $< $(CFLAGS) $(CBOR_FLAGS) $(INCLUDES)

$(BUILD)/cose.o: $(COSE)/cose.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) $(LIBS)

$(BUILD)/suit.o: $(SUIT)/suit.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES)

$(BUILD)/suit-cli.o: $(CURDIR)/suit-cli.c 
	$(CC) -c -o $@ $< $(CLFAGS) $(INCLUDES)

suit-cli: $(OBJS)
	$(CC) -o $(BUILD)/$@ $^ $(CFLAGS) $(LIBS)

$(BUILD)/demo-server.o: $(CURDIR)/demo-server.c
	$(CC) -c -o $@ $< $(CLFAGS) $(INCLUDES)

demo-server: $(BUILD)/demo-server.o $(BUILD)/encoder.o $(BUILD)/decoder.o
	$(CC) -o $(BUILD)/$@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	@rm -rf $(BUILD)	

