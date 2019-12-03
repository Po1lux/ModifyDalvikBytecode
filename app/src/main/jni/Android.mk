LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    :=modify
LOCAL_SRC_FILES :=modify.c
LOCAL_LDLIBS    :=-lm -llog
include $(BUILD_SHARED_LIBRARY)