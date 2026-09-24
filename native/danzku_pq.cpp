#include <android/log.h>
#define LOG_TAG "DanzKuPQ"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
extern "C" void danzku_pq_init() {
    LOGI("DanzKu PQ hook library loaded");
}
