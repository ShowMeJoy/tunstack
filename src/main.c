#include "tun.h"
#include "ipv4.h"
#include "icmp.h"
#include "udp.h"
#include "udp_reply.h"
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

    printf("TUN interface ready, fd=%d\n", tun_fd);

    unsigned char buf[BUF_SIZE];
    ssize_t nread;

    while (1) {
        nread = read(tun_fd, buf, sizeof(buf));
        if (nread < 0) {
            perror("read");
            break;
        }
        if (nread == 0) continue; // пустой пакет

        printf("\nRead %zd bytes\n", nread);
        hexdump(buf, nread > DUMP_LIMIT ? DUMP_LIMIT : nread);
        fflush(stdout);

        // Проверка на IPv4
        if (is_ipv4(buf, nread)) {
            parse_ipv4(buf, nread);

            // ICMP
            if (is_icmp(buf, nread)) {
                handle_icmp(buf, nread, tun_fd);
            }

            // UDP
            if (is_udp(buf, nread)) {
                handle_udp(buf, nread);
                handle_udp_reply(buf, nread, tun_fd);
            }
        } else {
            printf("Non-IPv4 packet, ignored\n");
        }
    }

    return 0;
}
