/*
 * vm_log.h — logging shim shared by the native container runtime.
 *
 *  - On Android (NDK/bionic): forwards to logcat with the per-TU LOG_TAG.
 *  - On host Linux dev containers (unit/integration tests, no liblog):
 *    falls back to stderr so the SAME sources compile everywhere.
 */
#ifndef VM_LOG_H_
#define VM_LOG_H_

#ifdef __ANDROID__

#include <android/log.h>

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,   LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,    LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,    LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,   LOG_TAG, __VA_ARGS__)

#else /* host build */

#include <stdio.h>

#define LOG_IMPL(level, fmt, ...)                                 \
    do { fprintf(stderr, "[" level "][" LOG_TAG "] " fmt "\n",    \
                 ##__VA_ARGS__); } while (0)

#define LOGV(fmt, ...) LOG_IMPL("V", fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) LOG_IMPL("D", fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) LOG_IMPL("I", fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) LOG_IMPL("W", fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) LOG_IMPL("E", fmt, ##__VA_ARGS__)

#endif /* __ANDROID__ */

#endif /* VM_LOG_H_ */
