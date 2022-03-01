
# Also see "include/mbedtls/mbedtls_config.h"
TOP_DIR=../..

CFLAGS	?= -O2
#WARNING_CFLAGS ?=  -Wall -Werror -Wextra -Wformat=2 -Wno-format-nonliteral -Wpedantic
WARNING_CFLAGS ?=  -Wall -Werror -Wextra -Wformat=2 -Wno-format-nonliteral
LDFLAGS ?=

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
LOCAL_CFLAGS = $(WARNING_CFLAGS) -I. -I.. -I$(TOP_DIR)/include -D_FILE_OFFSET_BITS=64
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

SOEXT_TLS=so.4

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

OBJS_TLS= \
	  debug.o \
	  net_sockets.o \
	  ssl_cache.o \
	  ssl_ciphersuites.o \
	  ssl_cli_pq.o \
	  ssl_cookie.o \
	  ssl_kem_pkwrap.o \
	  ssl_msg.o \
	  ssl_srv.o \
	  ssl_ticket.o \
	  ssl_tls.o \
	  ssl_tls13_keys.o \
	  # This line is intentionally left blank

#.SILENT:

.PHONY: all static shared clean

ifndef SHARED
all: static
else
all: shared 
endif

static: libmbedtls.a

shared: libmbedtls.$(DLEXT)


# tls
libmbedtls.a: $(OBJS_TLS)
	echo "${MAKE_INDENT}  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_TLS)
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
	echo "${MAKE_INDENT}  RL    $@"
	$(RL) $(RLFLAGS) $@
endif
endif

libmbedtls.$(SOEXT_TLS): $(OBJS_TLS)
	echo "${MAKE_INDENT}  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -L. -L$(TOP_DIR)/library/crypto -L$(TOP_DIR)/library/x509 -lmbedcrypto -lmbedx509 $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_TLS)

libmbedtls.so: libmbedtls.$(SOEXT_TLS)
	echo "${MAKE_INDENT}  LN    $@ -> $<"
	ln -sf $< $@


#libmbedtls.dylib: $(OBJS_TLS) libmbedx509.dylib
#	echo "${MAKE_INDENT}  LD    $@"
#	$(CC) -dynamiclib -L. -lmbedcrypto -lmbedx509 $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_TLS)

#libmbedtls.dll: $(OBJS_TLS) libmbedx509.dll
#	echo "${MAKE_INDENT}  LD    $@"
#	$(CC) -shared -Wl,-soname,$@ -Wl,--out-implib,$@.a -o $@ $(OBJS_TLS) -lws2_32 -lwinmm -lgdi32 -L. -lmbedcrypto -lmbedx509 -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

.c.o:
	echo "${MAKE_INDENT}  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

clean:
ifndef WINDOWS
	echo "  tls clean:" 
	rm -f *.o libmbedtls*
else
	if exist *.o del /Q /F *.o
	if exist libmbedtls* del /Q /F libmbedtls*
endif

