3rdparty_dir = $(dir $(lastword $(MAKEFILE_LIST)))
include $(3rdparty_dir)/everest/Makefile.inc
