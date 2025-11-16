/*
 * Utility functions implementation
 */

#include "util.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

char *trim(char *str) {
    char *end;

    /* Trim leading space */
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0) return str;

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    /* Write new null terminator */
    end[1] = '\0';

    return str;
}

int parse_ipv4(const char *str, char *out, size_t out_size) {
    if (!str || !out || out_size == 0) {
        return -1;
    }
    snprintf(out, out_size, "%s", str);
    return 0;
}

int parse_ipv6(const char *str, char *out, size_t out_size) {
    if (!str || !out || out_size == 0) {
        return -1;
    }
    snprintf(out, out_size, "%s", str);
    return 0;
}

int exec_cmd(const char *cmd) {
    log_debug("Executing: %s", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        log_error("Command failed with code %d: %s", ret, cmd);
    }
    return ret;
}

int read_file_line(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    if (fgets(buf, size, f) == NULL) {
        fclose(f);
        return -1;
    }

    fclose(f);

    /* Remove trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') {
        buf[len-1] = '\0';
    }

    return 0;
}

int daemonize(void) {
    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    }

    if (pid > 0) {
        /* Parent exits */
        exit(0);
    }

    /* Child continues */
    if (setsid() < 0) {
        return -1;
    }

    /* Fork again to prevent acquiring controlling terminal */
    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid > 0) {
        exit(0);
    }

    /* Change working directory */
    if (chdir("/") < 0) {
        return -1;
    }

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect to /dev/null */
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    return 0;
}

int write_pidfile(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        return -1;
    }

    fprintf(f, "%d\n", getpid());
    fclose(f);
    return 0;
}

int remove_pidfile(const char *path) {
    return unlink(path);
}
