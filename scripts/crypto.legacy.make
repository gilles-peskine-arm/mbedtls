# Helper code for the make build system in Mbed TLS.
# This file is only meant to exist for a short transition period.
# It may change or be removed without notice.
# Do not use it if you are not Mbed TLS!

# Assume that this makefile is located in a first-level subdirectory of the
# Mbed TLS root, and is accessed directly (not via VPATH or such).
# If this is not the case, TF_PSA_CRYPTO_PATH must be defined before
# including this file.
ifeq ($(origin TF_PSA_CRYPTO_PATH), undefined)
  # $(dir $(lastword $(MAKEFILE_LIST))) is the path to this file, possibly
  # a relative path, with a trailing slash. Strip off another directory
  # from that.
  TF_PSA_CRYPTO_PATH := $(patsubst %/,%,$(dir $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))))/tf-psa-crypto
endif

ifeq (,$(wildcard $(TF_PSA_CRYPTO_PATH)/core/psa_crypto.c))
  $(error $$(TF_PSA_CRYPTO_PATH)/core/psa_crypto.c not found)
endif

