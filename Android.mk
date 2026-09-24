LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := libdanzku_pq
LOCAL_SRC_FILES := native/danzku_pq.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := danzku-pq-injector
LOCAL_SRC_FILES := native/danzku_pq_injector.cpp
include $(BUILD_EXECUTABLE)
