THIRDPARTY_INCLUDES+=-I$(TOP_DIR)/3rdparty/everest/include -I$(EVEREST_TOP_DIR)/3rdparty/everest/include/everest -I$(TOP_DIR)/3rdparty/everest/include/everest/kremlib

THIRDPARTY_PKEY_OBJECTS+= \
	$(TOP_DIR)/3rdparty/everest/library/everest.o \
	$(TOP_DIR)/3rdparty/everest/library/x25519.o \
	$(TOP_DIR)/3rdparty/everest/library/Hacl_Curve25519_joined.o
