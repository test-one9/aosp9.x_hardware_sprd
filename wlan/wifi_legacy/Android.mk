LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifneq ($(filter VER_0_8_X VER_2_1_DEVEL,$(WPA_SUPPLICANT_VERSION)),)
LOCAL_CFLAGS += -DCONFIG_HOSTAPD_ADVANCE
endif

LOCAL_SRC_FILES:= \
    wifi_priv.c

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    liblog

LOCAL_MODULE := libsprd_wifi_priv
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

include $(BUILD_STATIC_LIBRARY)
