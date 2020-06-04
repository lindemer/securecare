SUIT ?= $(CURDIR)
COSE ?= $(CURDIR)/../cose
CBOR ?= $(CURDIR)/../../lib/NanoCBOR
BUILD ?= $(CURDIR)/build
LDIR ?= /usr/local/lib

CC ?= gcc
RM = rm -rf

SRCS = \
    $(CBOR)/src/encoder.c \
    $(CBOR)/src/decoder.c \
    $(COSE)/cose.c \
    $(SUIT)/suit.c \
    $(SUIT)/cli.c \

OBJS ?= \
    $(BUILD)/encoder.o \
    $(BUILD)/decoder.o \
    $(BUILD)/cose.o \
    $(BUILD)/suit.o \
    $(BUILD)/cli.o \

OPT = -O3 -g3
CFLAGS += $(OPT)
CFLAGS += -Wall -Werror
CBOR_FLAGS += -DNANOCBOR_BYTEORDER_HEADER=\"nanocbor/nanocbor.h\"
CBOR_FLAGS += -DNANOCBOR_HTOBE32_FUNC=__builtin_bswap32
CBOR_FLAGS += -DNANOCBOR_HTOBE64_FUNC=__builtin_bswap64
CBOR_FLAGS += -DNANOCBOR_BE64TOH_FUNC=__builtin_bswap64
INCLUDES += -I$(CBOR)/include
INCLUDES += -I$(COSE)
INCLUDES += -I.
LIBS = -lmbedtls -lmbedcrypto

default: mkdir suit

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

$(BUILD)/cli.o: $(SUIT)/cli.c 
	$(CC) -c -o $@ $< $(CLFAGS) $(INCLUDES)

suit: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	$(RM) $(BUILD)	

