/*
 * Hurricane Electric Tunnel Endpoint Auto-Update Client
 * Updates tunnel endpoint when client IPv4 address changes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#define VERSION "1.0.0"
#define HE_UPDATE_URL "https://ipv4.tunnelbroker.net/tstamp/"
#define IP_CHECK_URL "https://ipv4.icanhazip.com"

/* Response buffer for curl */
struct response_buffer {
    char *data;
    size_t size;
};

/* Write callback for curl */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *buf = (struct response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

/* Get current public IPv4 address */
static int get_public_ipv4(char *ip_buffer, size_t buf_size) {
    CURL *curl;
    CURLcode res;
    struct response_buffer response = {0};

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, IP_CHECK_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to get public IP: %s\n", curl_easy_strerror(res));
        free(response.data);
        return -1;
    }

    /* Remove trailing newline */
    if (response.data) {
        size_t len = strlen(response.data);
        while (len > 0 && (response.data[len-1] == '\n' || response.data[len-1] == '\r')) {
            response.data[--len] = '\0';
        }
        strncpy(ip_buffer, response.data, buf_size - 1);
        ip_buffer[buf_size - 1] = '\0';
        free(response.data);
        return 0;
    }

    free(response.data);
    return -1;
}

/* Update HE tunnel endpoint */
static int update_he_endpoint(const char *username, const char *password,
                              const char *tunnel_id, const char *new_ip) {
    CURL *curl;
    CURLcode res;
    struct response_buffer response = {0};
    char url[512];
    char userpwd[256];
    int ret = -1;

    /* Build URL: https://ipv4.tunnelbroker.net/tstamp/TUNNEL_ID */
    snprintf(url, sizeof(url), "%s%s", HE_UPDATE_URL, tunnel_id);
    snprintf(userpwd, sizeof(userpwd), "%s:%s", username, password);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* Optional: specify IP to update to */
    if (new_ip && strlen(new_ip) > 0) {
        char postfields[128];
        snprintf(postfields, sizeof(postfields), "myip=%s", new_ip);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
    }

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (http_code == 200) {
            printf("✓ Tunnel endpoint updated successfully\n");
            if (response.data && strstr(response.data, "good") != NULL) {
                ret = 0;
            } else if (response.data) {
                printf("Response: %s\n", response.data);
                ret = 0;  /* Consider success if HTTP 200 */
            }
        } else if (http_code == 401) {
            fprintf(stderr, "✗ Authentication failed: invalid username/password\n");
        } else {
            fprintf(stderr, "✗ Update failed with HTTP code: %ld\n", http_code);
            if (response.data) {
                fprintf(stderr, "Response: %s\n", response.data);
            }
        }
    } else {
        fprintf(stderr, "✗ Failed to update endpoint: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    free(response.data);

    return ret;
}

/* Read stored IP from cache file */
static int read_cached_ip(const char *cache_file, char *ip_buffer, size_t buf_size) {
    FILE *fp = fopen(cache_file, "r");
    if (!fp) {
        return -1;
    }

    if (fgets(ip_buffer, buf_size, fp) == NULL) {
        fclose(fp);
        return -1;
    }

    /* Remove trailing newline */
    size_t len = strlen(ip_buffer);
    while (len > 0 && (ip_buffer[len-1] == '\n' || ip_buffer[len-1] == '\r')) {
        ip_buffer[--len] = '\0';
    }

    fclose(fp);
    return 0;
}

/* Write IP to cache file */
static int write_cached_ip(const char *cache_file, const char *ip) {
    FILE *fp = fopen(cache_file, "w");
    if (!fp) {
        fprintf(stderr, "Warning: Could not write cache file: %s\n", cache_file);
        return -1;
    }

    fprintf(fp, "%s\n", ip);
    fclose(fp);
    return 0;
}

static void print_usage(const char *progname) {
    printf("Hurricane Electric Tunnel Endpoint Auto-Update Client v%s\n\n", VERSION);
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -u USERNAME    HE account username (required)\n");
    printf("  -p PASSWORD    HE account password (required)\n");
    printf("  -t TUNNEL_ID   HE tunnel ID (required)\n");
    printf("  -i IP          Specific IP to update to (optional, auto-detect if not provided)\n");
    printf("  -c CACHE_FILE  Cache file to track IP changes (default: /var/lib/v6-gatewayd/he-ip.cache)\n");
    printf("  -f             Force update even if IP hasn't changed\n");
    printf("  -v             Verbose output\n");
    printf("  -h             Show this help message\n\n");
    printf("Examples:\n");
    printf("  # Update with auto-detected IP\n");
    printf("  %s -u myuser -p mypass -t 940962\n\n", progname);
    printf("  # Update with specific IP\n");
    printf("  %s -u myuser -p mypass -t 940962 -i 1.2.3.4\n\n", progname);
    printf("  # Force update\n");
    printf("  %s -u myuser -p mypass -t 940962 -f\n\n", progname);
}

int main(int argc, char *argv[]) {
    char *username = NULL;
    char *password = NULL;
    char *tunnel_id = NULL;
    char *specified_ip = NULL;
    char *cache_file = "/var/lib/v6-gatewayd/he-ip.cache";
    int force_update = 0;
    int verbose = 0;
    int opt;

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "u:p:t:i:c:fvh")) != -1) {
        switch (opt) {
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 't':
                tunnel_id = optarg;
                break;
            case 'i':
                specified_ip = optarg;
                break;
            case 'c':
                cache_file = optarg;
                break;
            case 'f':
                force_update = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Validate required arguments */
    if (!username || !password || !tunnel_id) {
        fprintf(stderr, "Error: username, password, and tunnel_id are required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Get current IP */
    char current_ip[64] = {0};
    if (specified_ip) {
        strncpy(current_ip, specified_ip, sizeof(current_ip) - 1);
        if (verbose) {
            printf("Using specified IP: %s\n", current_ip);
        }
    } else {
        if (verbose) {
            printf("Detecting public IPv4 address...\n");
        }
        if (get_public_ipv4(current_ip, sizeof(current_ip)) != 0) {
            fprintf(stderr, "Failed to detect public IP address\n");
            return 1;
        }
        if (verbose) {
            printf("Detected IP: %s\n", current_ip);
        }
    }

    /* Check if IP has changed */
    char cached_ip[64] = {0};
    int ip_changed = 1;

    if (!force_update && read_cached_ip(cache_file, cached_ip, sizeof(cached_ip)) == 0) {
        if (strcmp(current_ip, cached_ip) == 0) {
            if (verbose) {
                printf("IP unchanged (%s), skipping update\n", current_ip);
            }
            ip_changed = 0;
        } else {
            if (verbose) {
                printf("IP changed: %s -> %s\n", cached_ip, current_ip);
            }
        }
    }

    if (!ip_changed && !force_update) {
        printf("No update needed\n");
        return 0;
    }

    /* Update HE tunnel endpoint */
    if (verbose) {
        printf("Updating HE tunnel %s to IP %s...\n", tunnel_id, current_ip);
    }

    if (update_he_endpoint(username, password, tunnel_id, current_ip) == 0) {
        /* Update cache file */
        write_cached_ip(cache_file, current_ip);
        printf("IP: %s\n", current_ip);
        return 0;
    } else {
        return 1;
    }
}
