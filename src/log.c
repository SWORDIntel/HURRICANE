/*
 * Logging system implementation
 */

#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static log_level_t current_level = LOG_LEVEL_INFO;

void log_init(const char *level_str) {
    if (!level_str) {
        current_level = LOG_LEVEL_INFO;
        return;
    }

    if (strcasecmp(level_str, "debug") == 0) {
        current_level = LOG_LEVEL_DEBUG;
    } else if (strcasecmp(level_str, "info") == 0) {
        current_level = LOG_LEVEL_INFO;
    } else if (strcasecmp(level_str, "warn") == 0) {
        current_level = LOG_LEVEL_WARN;
    } else if (strcasecmp(level_str, "error") == 0) {
        current_level = LOG_LEVEL_ERROR;
    }
}

void log_set_level(log_level_t level) {
    current_level = level;
}

static void log_msg(log_level_t level, const char *level_str, const char *fmt, va_list args) {
    if (level < current_level) {
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] [%s] ", time_buf, level_str);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg(LOG_LEVEL_DEBUG, "DEBUG", fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg(LOG_LEVEL_INFO, "INFO", fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg(LOG_LEVEL_WARN, "WARN", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg(LOG_LEVEL_ERROR, "ERROR", fmt, args);
    va_end(args);
}
