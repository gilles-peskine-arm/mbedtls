
# Also see "include/mbedtls/mbedtls_config.h"
TOP_DIR=../..

CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Wall -Werror -Wextra -Wformat=2 -Wno-format-nonliteral -Wpedantic
LDFLAGS ?=

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
LOCAL_CFLAGS = $(WARNING_CFLAGS) -I. -I.. -I../../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

ifdef DEBUG
LOCAL_CFLAGS += -g3
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

SOEXT_X509=so.4

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

OBJS_X509= \
	   x509.o \
	   x509_create.o \
	   x509_crl.o \
	   x509_crt.o \
	   x509_csr.o \
	   x509write_crt.o \
	   x509write_csr.o \
	   # This line is intentionally left blank

#.SILENT:

.PHONY: all static shared clean

ifndef SHARED
all: static
else
all: shared 
endif

static: libmbedx509.a

shared: libmbedx509.$(DLEXT)


# x509
libmbedx509.a: $(OBJS_X509)
	echo "${MAKE_INDENT}  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_X509)
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
	echo "${MAKE_INDENT}  RL    $@"
	$(RL) $(RLFLAGS) $@
endif
endif

libmbedx509.$(SOEXT_X509): $(OBJS_X509) 
	echo "${MAKE_INDENT}  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -L. -L$(TOP_DIR)/library/crypto -lmbedcrypto $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_X509)

libmbedx509.so: libmbedx509.$(SOEXT_X509)
	echo "${MAKE_INDENT}  LN    $@ -> $<"
	ln -sf $< $@


#libmbedx509.dylib: $(OBJS_X509) libmbedcrypto.dylib
#	echo "${MAKE_INDENT}  LD    $@"
#	$(CC) -dynamiclib -L. -lmbedcrypto  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_X509)

#libmbedx509.dll: $(OBJS_X509) libmbedcrypto.dll
#	echo "${MAKE_INDENT}  LD    $@"
#	$(CC) -shared -Wl,-soname,$@ -Wl,--out-implib,$@.a -o $@ $(OBJS_X509) -lws2_32 -lwinmm -lgdi32 -L. -lmbedcrypto -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)


.c.o:
	echo "${MAKE_INDENT}  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

clean:
ifndef WINDOWS
	echo "  x509 clean:" 
	rm -f *.o libmbedx509*
else
	if exist *.o del /Q /F *.o
	if exist libmbedx509* del /Q /F libmbedx509*
endif

