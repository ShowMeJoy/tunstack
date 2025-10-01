#include "tun.h"
#include "ipv4.h"
#include "icmp.h"
#include "udp.h"
#include "udp_reply.h"
#include "tap.h"
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <net/if.h> 

#define BUF_SIZE 2000
#define DUMP_LIMIT 256

static void hexdump(const unsigned char *b, int n) {
    for (int i = 0; i < n; ++i) {
        printf("%02x ", b[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    if (n % 16) printf("\n");
}

int main() {
    char devname[IFNAMSIZ] = "tun1";
    int tun_fd = tun_alloc(devname);
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to allocate TUN interface\n");
        return 1;
    }

    char ifname[IFNAMSIZ] = "tap0";
    int tap_fd = tap_alloc(ifname);
    if (tap_fd < 0) {
        fprintf(stderr, "Failed to allocate TAP interface\n");
        return 1;
    }

    unsigned char buf[BUF_SIZE];
    ssize_t n_tun = 0, n_tap = 0;
    fd_set rfds;
    int maxfd = (tun_fd > tap_fd ? tun_fd : tap_fd) + 1;

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(tun_fd, &rfds);
        FD_SET(tap_fd, &rfds);

        int ret = select(maxfd, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(tun_fd, &rfds)) {
            n_tun = read(tun_fd, buf, sizeof(buf));
            if (n_tun > 0) {
                printf("\n[TUN] Read %zd bytes\n", n_tun);
                hexdump(buf, n_tun > DUMP_LIMIT ? DUMP_LIMIT : n_tun);
            }
        }

        if (FD_ISSET(tap_fd, &rfds)) {
            n_tap = read(tap_fd, buf, sizeof(buf));
            if (n_tap > 0) {
                printf("\n[TAP] Read %zd bytes\n", n_tap);
                hexdump(buf, n_tap > DUMP_LIMIT ? DUMP_LIMIT : n_tap);
            }
        }

        // Проверка на IPv4
        if (is_ipv4(buf, n_tun)) {
            parse_ipv4(buf, n_tun);

            // ICMP
            if (is_icmp(buf, n_tun)) {
                handle_icmp(buf, n_tun, tun_fd);
            }

            // UDP
            if (is_udp(buf, n_tun)) {
                handle_udp(buf, n_tun);
                handle_udp_reply(buf, n_tun, tun_fd);
            }
        } else {
            printf("Non-IPv4 packet, ignored\n");
        }
    }

    return 0;
}
