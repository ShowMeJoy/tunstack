#include "ipv4.h"
#include <stdio.h>
#include <stdint.h>

#define IPV4_MIN_LEN 20

// packet check
bool is_ipv4(unsigned char *buf, size_t len) {
    if (len < IPV4_MIN_LEN) return false;
    unsigned char version = buf[0] >> 4;
    return version == 4;
}

// decompile IPv4 packet
void parse_ipv4(unsigned char *buf, size_t len) {
    if (len < IPV4_MIN_LEN) return;

    // move 4 bytes right to get version
    unsigned char version = buf[0] >> 4;
    unsigned char ihl = buf[0] & 0x0F;
    unsigned char tos = buf[1];
    uint16_t tot_len = (buf[2] << 8) | buf[3];
    uint8_t ttl = buf[8];
    uint8_t protocol = buf[9];
    uint32_t saddr = (buf[12] << 24) | (buf[13] << 16) | (buf[14] << 8) | buf[15];
    uint32_t daddr = (buf[16] << 24) | (buf[17] << 16) | (buf[18] << 8) | buf[19];

    printf("IPv4 packet: version=%u, ihl=%u, tos=%u, tot_len=%u, ttl=%u, protocol=%u, saddr=%u, daddr=%u\n",
            version, ihl, tos, tot_len, ttl, protocol, saddr, daddr);
    
    /*
    saddr = 0xC0A80101 = 192.168.1.1
    (saddr >> 16) & 0xFF = 0xA8 = 168

      1100 0000 1010 1000
    & 0000 0000 1111 1111
    ---------------------
      0000 0000 1010 1000   = 168
    */
    printf("Src IP: %u.%u.%u.%u\n",
           (saddr >> 24) & 0xFF, (saddr >> 16) & 0xFF, (saddr >> 8) & 0xFF, saddr & 0xFF);
    printf("Dst IP: %u.%u.%u.%u\n",
           (daddr >> 24) & 0xFF, (daddr >> 16) & 0xFF, (daddr >> 8) & 0xFF, daddr & 0xFF);
}
