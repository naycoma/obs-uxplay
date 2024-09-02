#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>

extern const char *PLUGIN_NAME;
extern const char *PLUGIN_VERSION;

#define LOGD(...) obs_log(LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) obs_log(LOG_INFO, __VA_ARGS__)
#define LOGW(...) obs_log(LOG_WARNING, __VA_ARGS__)
#define LOGE(...) obs_log(LOG_ERROR, __VA_ARGS__)

void obs_log(int log_level, const char *format, ...);
extern void blogva(int log_level, const char *format, va_list args);

#ifdef __cplusplus
}
#endif