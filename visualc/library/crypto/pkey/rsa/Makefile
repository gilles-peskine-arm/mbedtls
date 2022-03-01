
# Also see "include/mbedtls/mbedtls_config.h"
TOP_DIR=../../../..

CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Werror -Wall -Wextra -Wformat=2 -Wno-format-nonliteral -Wpedantic
LDFLAGS ?=

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
LOCAL_CFLAGS = $(WARNING_CFLAGS) -I. -I.. -I$(TOP_DIR)/library -I$(TOP_DIR)/library/crypto -I$(TOP_DIR)/include -D_FILE_OFFSET_BITS=64
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

# To compile as a shared library:
ifdef SHARED
# all code is position-indep with mingw, avoid warning about useless flag
ifndef WINDOWS_BUILD
LOCAL_CFLAGS += -fPIC -fpic
endif
endif

SOEXT_PKEY=so.10

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

DLEXT ?= so
ifdef WINDOWS_BUILD
# Windows shared library extension:
DLEXT = dll
else ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
# Mac OS X shared library extension:
DLEXT = dylib
endif
endif

OBJS_PKEY_RSA = \
	     rsa.o \
	     rsa_alt_helpers.o \
	     rsa_mbed_wrap.o
	     # This line is intentionally left blank

#.SILENT:

.PHONY: all static clean

all: static

static: libmbedpkeyrsa.a 

# crypto
libmbedpkeyrsa.a: $(OBJS_PKEY_RSA) 
	echo "${MAKE_INDENT}  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_PKEY_RSA)
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
	echo "${MAKE_INDENT}  rsa clean:" 
	rm -f *.o libmbedpkeyrsa*
	rm -f $(THIRDPARTY_PKEY_OBJECTS)
else
	if exist *.o del /Q /F *.o
	if exist libmbedpkeyrsa* del /Q /F libmbedpkeyrsa*
endif

