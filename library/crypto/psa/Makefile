
# Also see "include/mbedtls/mbedtls_config.h"
TOP_DIR=../../..

CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Wall -Wextra -Wformat=2 -Wno-format-nonliteral
LDFLAGS ?=

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
INCLUDE_DIRS = -I. -I$(TOP_DIR)/include -I$(TOP_DIR)/library -I$(TOP_DIR)/library/crypto -I$(TOP_DIR)/library/crypto/hash -I$(TOP_DIR)/library/crypto/pkey
LOCAL_CFLAGS = $(WARNING_CFLAGS) $(INCLUDE_DIRS) -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

ifdef DEBUG
LOCAL_CFLAGS += -g3 -DMAKE_DEBUG_ENABLED
endif

# MicroBlaze specific options:
# CFLAGS += -mno-xl-soft-mul -mxl-barrel-shift

# To compile on Plan9:
# CFLAGS += -D_BSD_EXTENSION

PERL ?= perl

# if were running on Windows build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
else ifeq ($(shell uname -s),Darwin)
ifeq ($(AR),ar)
APPLE_BUILD ?= 1
endif
endif

# Set AR_DASH= (empty string) to use an ar implementation that does not accept
# the - prefix for command line options (e.g. llvm-ar)
AR_DASH ?= -

ARFLAGS = $(AR_DASH)src
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
ARFLAGS = $(AR_DASH)Src
RLFLAGS = -no_warning_for_no_symbols -c
RL ?= ranlib
endif
endif

OBJS_PSA = \
	     psa_crypto.o \
	     psa_crypto_aead.o \
	     psa_crypto_cipher.o \
	     psa_crypto_client.o \
	     psa_crypto_driver_wrappers.o \
	     psa_crypto_ecp.o \
	     psa_crypto_hash.o \
	     psa_crypto_mac.o \
	     psa_crypto_rsa.o \
	     psa_crypto_se.o \
	     psa_crypto_slot_management.o \
	     psa_crypto_storage.o \
	     psa_its_file.o
	     # This line is intentionally left blank

#.SILENT:
.PHONY: all clean

all: libmbedpsa.a 

# crypto
libmbedpsa.a: $(OBJS_PSA)
	echo "${MAKE_INDENT}  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_PSA)
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
	echo "${MAKE_INDENT}  RL    $@"
	$(RL) $(RLFLAGS) $@
endif
endif

.c.o:
	echo "${MAKE_INDENT}  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

clean:
ifndef WINDOWS
	echo "${MAKE_INDENT}  psa clean:" 
	rm -f *.o libmbedpsa*
else
	if exist *.o del /Q /F *.o
	if exist libmbedpsa* del /Q /F libmbedpsa*
endif

