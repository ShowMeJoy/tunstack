#include "udp.h"
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define IPV4_MIN_HDR 20
#define UDP_HDR_LEN 8

bool is_udp(const unsigned char *buf, size_t len) {
    if (len < IPV4_MIN_HDR + UDP_HDR_LEN) return false;

    unsigned char version = buf[0] >> 4;
    if (version != 4) return false;

    unsigned int ihl = buf[0] & 0x0F;
    size_t ip_hdr_len = ihl * 4;
    if (len < ip_hdr_len + UDP_HDR_LEN) return false;

    uint8_t proto = buf[9];
    return proto == 17; // 17 == UDP
}

void handle_udp(const unsigned char *buf, size_t len) {
    if (!is_udp(buf, len)) return;

    unsigned int ihl = buf[0] & 0x0F;
    size_t ip_hdr_len = ihl * 4;

    const unsigned char *udp = buf + ip_hdr_len;
    uint16_t src_port = (udp[0] << 8) | udp[1];
    uint16_t dst_port = (udp[2] << 8) | udp[3];
    uint16_t udp_len = (udp[4] << 8) | udp[5];

    printf("UDP packet: src_port=%u dst_port=%u len=%u\n",
           src_port, dst_port, udp_len);

    size_t payload_len = udp_len > UDP_HDR_LEN ? udp_len - UDP_HDR_LEN : 0;
    const unsigned char *payload = udp + UDP_HDR_LEN;

    if (payload_len > 0) {
        printf("UDP payload (%zu bytes): ", payload_len);
        for (size_t i = 0; i < payload_len && i < 32; i++) {
            printf("%02x ", payload[i]);
        }
        if (payload_len > 32) printf("...");
        printf("\n");
    }
}
