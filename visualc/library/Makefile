
# Also see "include/mbedtls/mbedtls_config.h"
MAKE_INDENT ?= ""
LIBRARY_MAKE_INDENT:=$(MAKE_INDENT)

PERL ?= perl

# if were running on Windows build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
else ifeq ($(shell uname -s),Darwin)
ifeq ($(AR),ar)
APPLE_BUILD ?= 1
endif
endif


SUBDIR_LIBARY = \
	     crypto \
	     x509 \
	     tls


.SILENT:

.PHONY: all clean

ifdef SHARED
all: subdirs_library_shared 
#all: subdirs_library_shared subdirs_library_static
else
all: subdirs_library_static 
endif

# subdirs 
subdirs_library_static: 
	#echo "$(MAKE_INDENT)make crypto1:" 
	for subdir in $(SUBDIR_LIBARY); do \
		echo "$(LIBRARY_MAKE_INDENT)  make static library/$$subdir:" ; \
		MAKE_INDENT="$(LIBRARY_MAKE_INDENT)  " make -C $$subdir || exit 1; \
	done

subdirs_library_shared:
	#echo "$(MAKE_INDENT)make crypto1:" 
	for subdir in $(SUBDIR_LIBARY); do \
		echo "$(LIBRARY_MAKE_INDENT)  make shared library/$$subdir:" ; \
		MAKE_INDENT="$(LIBRARY_MAKE_INDENT)  " SHARED=Y make -C $$subdir CFLAGS=-fPIC || exit 1; \
	done
	

clean:
ifndef WINDOWS
	echo ""
	echo "mbedtls library clean:" 
	for subdir in $(SUBDIR_LIBARY); do \
		echo "make -C $$subdir clean"; \
		MAKE_INDENT="  " make -C $$subdir clean; \
	done
else
	if exist *.o del /Q /F *.o
	if exist libmbed* del /Q /F libmbed*
	del /Q /F del_errors_out_if_the_file_list_is_empty_but_not_if_a_file_does_not_exist $(subst /,\,$(THIRDPARTY_CRYPTO_OBJECTS))
endif

neat: clean
	make -C crypto neat 

