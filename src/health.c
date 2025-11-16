/*
 * Health check system implementation
 * IPv6 connectivity and reachability testing
 */

#include "health.h"
#include "log.h"
#include "v6gw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <errno.h>

#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY 129

static uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    unsigned int sum = 0;
    uint16_t result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int health_init(void) {
    log_info("Initializing health check system");
    return 0;
}

int health_ping_v6(const char *target, int *latency_ms) {
    int sockfd;
    struct sockaddr_in6 addr;
    struct icmp6_hdr icmp_hdr;
    char recv_buf[1024];
    struct timeval tv_start, tv_end, tv_timeout;
    fd_set read_fds;

    /* Create raw ICMPv6 socket */
    sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sockfd < 0) {
        log_error("Failed to create ICMPv6 socket: %s (need root/CAP_NET_RAW)", strerror(errno));
        return -1;
    }

    /* Set socket timeout */
    tv_timeout.tv_sec = 2;
    tv_timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

    /* Setup target address */
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, target, &addr.sin6_addr) != 1) {
        log_error("Invalid IPv6 address: %s", target);
        close(sockfd);
        return -1;
    }

    /* Build ICMPv6 Echo Request */
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    icmp_hdr.icmp6_code = 0;
    icmp_hdr.icmp6_id = getpid() & 0xFFFF;
    icmp_hdr.icmp6_seq = 1;
    icmp_hdr.icmp6_cksum = 0;

    /* Send Echo Request */
    gettimeofday(&tv_start, NULL);

    ssize_t sent = sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        log_error("Failed to send ICMPv6 packet: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    /* Wait for Echo Reply */
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    int ret = select(sockfd + 1, &read_fds, NULL, NULL, &tv_timeout);
    if (ret <= 0) {
        log_warn("ICMPv6 ping timeout to %s", target);
        close(sockfd);
        return -1;
    }

    /* Receive reply */
    ssize_t received = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
    gettimeofday(&tv_end, NULL);
    close(sockfd);

    if (received < 0) {
        log_error("Failed to receive ICMPv6 reply");
        return -1;
    }

    /* Calculate latency */
    long ms = (tv_end.tv_sec - tv_start.tv_sec) * 1000 +
              (tv_end.tv_usec - tv_start.tv_usec) / 1000;

    if (latency_ms) {
        *latency_ms = (int)ms;
    }

    log_debug("ICMPv6 ping to %s: %ld ms", target, ms);
    return 0;
}

int health_check_all(health_status_t *status) {
    if (!status) {
        return -1;
    }

    memset(status, 0, sizeof(*status));
    status->last_check = time(NULL);

    /* Check IPv6 connectivity by ping to known hosts */
    const char *test_hosts[] = {
        "2001:4860:4860::8888",  /* Google DNS */
        "2606:4700:4700::1111",  /* Cloudflare DNS */
        NULL
    };

    int latency;
    for (int i = 0; test_hosts[i] != NULL; i++) {
        if (health_ping_v6(test_hosts[i], &latency) == 0) {
            status->v6_reachable = true;
            status->v6_latency_ms = latency;
            break;
        }
    }

    /* Count active tunnels */
    for (int i = 0; i < g_ctx.tunnel_count; i++) {
        if (g_ctx.tunnels[i].state == TUNNEL_STATE_UP) {
            status->active_tunnels++;
        }
    }

    return 0;
}

void health_cleanup(void) {
    log_info("Cleaning up health check system");
}
