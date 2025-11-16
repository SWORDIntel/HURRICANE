/*
 * Logging system
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} log_level_t;

/* Initialize logging */
void log_init(const char *level_str);

/* Set log level */
void log_set_level(log_level_t level);

/* Log functions */
void log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* LOG_H */
