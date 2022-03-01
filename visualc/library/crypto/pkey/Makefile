
# Also see "include/mbedtls/mbedtls_config.h"
TOP_DIR=../../..

MAKE_INDENT ?= ""
PKEY_MAKE_INDENT:=$(MAKE_INDENT)

CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Werror -Wall -Wextra -Wformat=2 -Wno-format-nonliteral  -Wpedantic
LDFLAGS ?=

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
LOCAL_CFLAGS = $(WARNING_CFLAGS) -I. -I$(TOP_DIR)/library -I$(TOP_DIR)/library/crypto -I$(TOP_DIR)/include -D_FILE_OFFSET_BITS=64
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

SUBDIR_PKEY= \
	     rsa \
	     ec \
	     kyber \
	     dilithium
	     
	     
TEMP_DIR=temp_pkey_dir
SUBDIR_LIBS :=$(foreach subdir, $(SUBDIR_PKEY), $(subdir)/libmbedpkey$(subdir).a ) 
TMPDIR_OBJS :=$(foreach subdir, $(SUBDIR_PKEY), $(TEMP_DIR)/$(subdir)/*.o ) 


OBJS_PKEY= \
	     asn1parse.o \
	     asn1write.o \
	     bignum.o \
	     dhm.o \
	     pem.o \
	     pkpq.o \
	     pkpq_wrap.o \
	     pkpq_parse.o \
	     pkpq_write.o \
	     pkcs12.o \
	     pkcs5.o \
	     # This line is intentionally left blank

SRCS_PKEY:=$(OBJS_PKEY:%.o=%.c) 


include $(TOP_DIR)/3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)
THIRDPARTY_PKEY_DEPS:=$(THIRDPARTY_PKEY_OBJECTS:%.o=%.d) 
OBJS_PKEY+=$(THIRDPARTY_PKEY_OBJECTS)


.SILENT:

.PHONY: all static shared clean

all: static

static: subdir_pkey libmbedpkey.a 

#subdir targets 
subdir_pkey:
	# echo "$(SUBDIR_LIBS)"
	for subdir in $(SUBDIR_PKEY); do \
		echo "$(MAKE_INDENT)  make pkey/$$subdir:" ; \
		MAKE_INDENT="$(PKEY_MAKE_INDENT)  " make -C $$subdir || exit 1; \
	done


libmbedpkey.a: clean_temp_dirs $(OBJS_PKEY)  $(SUBDIR_LIBS)
	@# combine the archives from all subdirs (There should be a better way to do this) 
	#echo "$(TMPDIR_OBJS)"
	if [ ! -d "$(TEMP_DIR)" ]; then \
	    mkdir $(TEMP_DIR); \
	fi
	cd $(TEMP_DIR) ; \
	for subdir in $(SUBDIR_PKEY); do \
		if [ ! -d "$$subdir" ]; then \
		    mkdir $$subdir; \
		fi; \
		cd $$subdir; \
		$(AR) x ../../$$subdir/libmbedpkey$$subdir.a; \
		for obj in *.o; do \
			mv $$obj $$subdir"_ZZZZ_"$$obj; \
		done; \
		cd ..;\
	done; \
	cd ..

	echo "${MAKE_INDENT}  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_PKEY) $(TMPDIR_OBJS)

%.o:%.c
	echo "${MAKE_INDENT}  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c -MMD -MP $< -o $@ 
	#$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

-include $(SRCS_PKEY:.c=.d)

clean_temp_dirs: 
	# clean the object files in the temp directory
	for subdir in $(SUBDIR_PKEY); do \
		rm -f $(TEMP_DIR)/*.o; \
		rm -f $(TEMP_DIR)/$$subdir/*.o; \
	done 


clean: clean_temp_dirs
ifndef WINDOWS
	echo "${MAKE_INDENT}  pkey clean:" 
	rm -f *.o *.d libmbedpkey*
	rm -f $(THIRDPARTY_PKEY_OBJECTS) $(THIRDPARTY_PKEY_DEPS)
	for subdir in $(SUBDIR_PKEY); do \
		MAKE_INDENT="$(PKEY_MAKE_INDENT)  " make -C $$subdir clean; \
	done
else
	if exist *.o del /Q /F *.o
	if exist *.d del /Q /F *.d
	if exist libmbedpkey* del /Q /F libmbedpkey*
	del /Q /F del_errors_out_if_the_file_list_is_empty_but_not_if_a_file_does_not_exist $(subst /,\,$(THIRDPARTY_PKEY_OBJECTS))
endif

