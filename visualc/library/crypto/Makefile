
# Also see "include/mbedtls/mbedtls_config.h"
TOP_DIR=../..
MAKE_INDENT ?= ""
CRYPTO_MAKE_INDENT:=$(MAKE_INDENT)

CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Wall -Wextra -Wformat=2 -Wno-format-nonliteral -Wpedantic
LDFLAGS ?=

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
LOCAL_CFLAGS = $(WARNING_CFLAGS) -I. -I./pkey -I.. -I$(TOP_DIR)/include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

ifdef DEBUG
LOCAL_CFLAGS += -g3 -DMAKE_DEBUG_ENABLED
endif

TEMP_DIR=temp_crypto_dir

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

SOEXT_CRYPTO=so.10

# Set AR_DASH= (empty string) to use an ar implementation that does not accept
# the - prefix for command line options (e.g. llvm-ar)
AR_DASH ?= -

ARFLAGS = $(AR_DASH)src
ARFLAGS_COMB = $(AR_DASH)sr
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

SUBDIR_CRYPTO= \
	     pkey \
	     skey \
	     hash \
	     rng \
	     kdf \
	     psa

SUBDIR_LIBS :=$(foreach subdir, $(SUBDIR_CRYPTO), $(subdir)/libmbed$(subdir).a ) 

OBJS_CRYPTO= \
	     base64.o \
	     crypto_util.o \
	     error.o \
	     memory_buffer_alloc.o \
	     mps_reader.o \
	     mps_trace.o \
	     nist_kw.o \
	     oid.o \
	     padlock.o \
	     platform.o \
	     platform_util.o \
	     threading.o \
	     timing.o \
	     version.o \
	     version_features.o
	     # This line is intentionally left blank


.SILENT:

.PHONY: all static shared clean

ifndef SHARED
all: static
else
all: shared 
endif

static: subdir_crypto libmbedcrypto.a 

shared: subdir_crypto libmbedcrypto.$(DLEXT) 

#subdir targets 
subdir_crypto:
	#echo "$(MAKE_INDENT)make crypto1:" 
	for subdir in $(SUBDIR_CRYPTO); do \
		echo "$(MAKE_INDENT)  make pkey/$$subdir:" ; \
		MAKE_INDENT="$(CRYPTO_MAKE_INDENT)  " make -C $$subdir || exit 1; \
	done

# crypto
libmbedcrypto.a: $(OBJS_CRYPTO)  $(SUBDIR_LIBS)
	@# combine the archives from all subdirs (There should be a better way to do this) 
	if [ ! -d "$(TEMP_DIR)" ]; then \
	    mkdir $(TEMP_DIR); \
	fi
	cd $(TEMP_DIR) ; \
	rm -f *.o ; \
	for subdir in $(SUBDIR_CRYPTO); do \
		$(AR) x ../$$subdir/libmbed$$subdir.a; \
	done; \
	cd ..

	echo "${MAKE_INDENT}  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_CRYPTO) $(TEMP_DIR)/*.o 
	
	#p $(PKEY_LIB) $@ 
	#(AR) $(ARFLAGS_COMB) $@ $(OBJS_CRYPTO) 
	#$(AR) $(ARFLAGS) $@ $(OBJS_CRYPTO) pkey/*.o 
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
	echo "${MAKE_INDENT}  RL    $@"
	$(RL) $(RLFLAGS) $@
endif
endif


libmbedcrypto.$(SOEXT_CRYPTO): $(OBJS_CRYPTO) $(SUBDIR_LIBS)
	echo "${MAKE_INDENT}  LD    $@"
	$(CC) -shared -Wl,-soname,$@ $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_CRYPTO) -Wl,--whole-archive $(SUBDIR_LIBS) -Wl,--no-whole-archive

#-include $(SUBDIR_LIBS)

libmbedcrypto.so: libmbedcrypto.$(SOEXT_CRYPTO)
	echo "${MAKE_INDENT}  LN    $@ -> $<"
	ln -sf $< $@

libmbedcrypto.dylib: $(OBJS_CRYPTO)
	echo "${MAKE_INDENT}  LD    $@"
	$(CC) -dynamiclib $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_CRYPTO)

libmbedcrypto.dll: $(OBJS_CRYPTO)
	echo "${MAKE_INDENT}  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -Wl,--out-implib,$@.a -o $@ $(OBJS_CRYPTO) -lws2_32 -lwinmm -lgdi32 -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

.c.o:
	echo "${MAKE_INDENT}  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<


.PHONY: generated_files
GENERATED_FILES = error.c version_features.c
generated_files: $(GENERATED_FILES)

error.c: $(TOP_DIR)/scripts/generate_errors.pl
error.c: $(TOP_DIR)/scripts/data_files/error.fmt
error.c: $(filter-out %config%,$(wildcard $(TOP_DIR)/include/mbedtls/*.h))
error.c:
	echo "${MAKE_INDENT}  Gen   $@"
	$(PERL) $(TOP_DIR)/scripts/generate_errors.pl

version_features.c: $(TOP_DIR)/scripts/generate_features.pl
version_features.c: $(TOP_DIR)/scripts/data_files/version_features.fmt
## The generated file only depends on the options that are present in mbedtls_config.h,
## not on which options are set. To avoid regenerating this file all the time
## when switching between configurations, don't declare mbedtls_config.h as a
## dependency. Remove this file from your working tree if you've just added or
## removed an option in mbedtls_config.h.
#version_features.c: ../include/mbedtls/mbedtls_config.h
version_features.c:
	echo "${MAKE_INDENT}  Gen   $@"
	$(PERL) $(TOP_DIR)/scripts/generate_features.pl


clean:
ifndef WINDOWS
	echo "  crypto clean:"
	rm -f *.o libmbedcrypto*
	for subdir in $(SUBDIR_CRYPTO); do \
		MAKE_INDENT="  " make -C $$subdir clean; \
	done
	rm -f $(TEMP_DIR)/*.o
else
	if exist *.o del /Q /F *.o
	if exist libmbedcrypto* del /Q /F libmbedcrypto*
endif

neat: clean
ifndef WINDOWS
	rm -f $(GENERATED_FILES)
else
	for %f in ($(subst /,\,$(GENERATED_FILES))) if exist %f del /Q /F %f
endif
