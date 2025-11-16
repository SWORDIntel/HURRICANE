/*
 * Utility functions
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* String utilities */
char *trim(char *str);
int parse_ipv4(const char *str, char *out, size_t out_size);
int parse_ipv6(const char *str, char *out, size_t out_size);

/* Network utilities */
int exec_cmd(const char *cmd);
int read_file_line(const char *path, char *buf, size_t size);

/* Daemonize process */
int daemonize(void);

/* PID file management */
int write_pidfile(const char *path);
int remove_pidfile(const char *path);

#endif /* UTIL_H */
