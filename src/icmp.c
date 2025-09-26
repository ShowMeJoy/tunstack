#include "icmp.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define IPV4_MIN_LEN 20
#define ICMP_MIN_LEN 8

// compute 16-bit one's complement checksum
static uint16_t csum16(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;

    while (len >= 2) {
        /* 
         * Network TO Host Short
         * Сonvert uint16_t from network byte order to host byte order
         */ 
        sum += ntohs(*ptr);
        ++ptr;
        len -= 2;
    }
    if (len == 1) {
        // leftover byte
        uint16_t last = ((uint8_t *)ptr)[0];
        sum += last << 8;
    }
        /* 
         * Folding:
         * if sum = 0x1E00A
         * sum & 0xFFFF = 0xE00A
         * sum >> 16 = 0x1
         * 0xE00A + 0x1 = 0xE00B
        */ 
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        /*
         * Inversion:
         * ~(0xE00B) = 0x1FF4 -> It's a checksum
         * Then we can prove it -> 0x1FF4 + 0xE00B = 1
         */
        return (uint16_t)(~sum) & 0xFFFF;
}

// Check if buffer contains IPv4 ICMP packet (Echo request or Reply)
bool is_icmp(unsigned char *buf, size_t len) {
    if (len < IPV4_MIN_LEN + ICMP_MIN_LEN) return false;
    unsigned int version = buf[0] >> 4;
    if (version != 4) return false;

    // IHL in 32-bit words
    unsigned int ihl = buf[0] & 0x0F;
    size_t ip_hdr_len = ihl * 4;
    if (len < ip_hdr_len + ICMP_MIN_LEN) return false;

    uint8_t proto = buf[0];
    return proto == 1;
}

// Handle ICMP Echo Request: create Echo Reply and write to tun_fd
void handle_icmp(unsigned char *buf, size_t len, int tun_fd) {
    if (!is_icmp(buf, len)) return;

    // parse IP header
    unsigned char ihl = buf[0] & 0x0F;
    size_t ip_hdr_len = ihl * 4;
    if (ip_hdr_len < IPV4_MIN_LEN || len <  ip_hdr_len + ICMP_MIN_LEN) return;

    uint16_t total_len = (buf[2] << 8) | buf[3];
    if (total_len > len) total_len = len; // be safe

    unsigned char *icmp = buf + ip_hdr_len;
    uint8_t icmp_type = icmp[0];
    uint8_t icmp_code = icmp[1];

    if (!(icmp_type == 8 && icmp_code == 0)) {
        return;
    }

    uint8_t reply[2000];
    if (total_len > sizeof(reply)) {
        return;
    }
    memcpy(reply, buf, total_len);

    // Swap IP src/dst
    for (int i = 0; i < 4; ++i) {
        uint8_t t = reply[12 + i];
        reply[12 + i] = reply[16 + i];
        reply[16 + i] = t;
    }

    // Set TTL to a typical reply value (64)
    reply[8] = 64;

    // Recalculate IP header checksum:
    // zero checksum field (bytes 10..11) then compute
    reply[10] = 0;
    reply[11] = 0;
    uint16_t ip_checksum = csum16(reply, (reply[0] & 0x0F) * 4);
    // store in network byte order
    reply[10] = (ip_checksum >> 8) & 0xFF;
    reply[11] = ip_checksum & 0xFF;

    // Build ICMP reply: type = 0 (Echo Reply), code = 0
    size_t icmp_offset = ip_hdr_len;
    reply[icmp_offset + 0] = 0; // type = 0 (Echo Reply)
    reply[icmp_offset + 1] = 0; // code = 0

    // zero ICMP checksum then compute over ICMP header + data
    reply[icmp_offset + 2] = 0;
    reply[icmp_offset + 3] = 0;
    size_t icmp_len = total_len - ip_hdr_len;
    uint16_t icmp_ck = csum16(reply + icmp_offset, icmp_len);
    // store checksum in network order
    reply[icmp_offset + 2] = (icmp_ck >> 8) & 0xFF;
    reply[icmp_offset + 3] = icmp_ck & 0xFF;

    // write back to TUN (no extra headers)
    ssize_t w = write(tun_fd, reply, total_len);
    if (w < 0) {
        perror("write(tun_fd)");
    } else {
        printf("ICMP: replied %zd bytes\n", w);
    }
}
