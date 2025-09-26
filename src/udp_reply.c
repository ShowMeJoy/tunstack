#include "udp_reply.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>

// Вспомогательная функция для пересчета 16-бит контрольной суммы
static uint16_t csum16(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;

    while (len >= 2) {
        sum += ntohs(*ptr);
        ptr++;
        len -= 2;
    }
    if (len == 1) sum += ((uint8_t*)ptr)[0] << 8;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum) & 0xFFFF;
}

// Обрабатываем UDP-пакет и отправляем ответ
void handle_udp_reply(const unsigned char *buf, size_t len, int tun_fd) {
    if (len < 28) return; // IPv4+UDP минимальная длина

    unsigned char reply[2000];
    if (len > sizeof(reply)) return;

    memcpy(reply, buf, len);

    unsigned int ihl = reply[0] & 0x0F;
    size_t ip_hdr_len = ihl * 4;

    // uint16_t total_len = (reply[2] << 8) | reply[3];

    // swap IP src/dst
    for (int i = 0; i < 4; ++i) {
        uint8_t t = reply[12+i];
        reply[12+i] = reply[16+i];
        reply[16+i] = t;
    }

    // TTL
    reply[8] = 64;

    // Обнулить IP checksum и пересчитать
    reply[10] = 0;
    reply[11] = 0;
    uint16_t ip_ck = csum16(reply, ip_hdr_len);
    reply[10] = (ip_ck >> 8) & 0xFF;
    reply[11] = ip_ck & 0xFF;

    // swap UDP ports
    uint8_t *udp = reply + ip_hdr_len;
    uint16_t src_port = (udp[0] << 8) | udp[1];
    uint16_t dst_port = (udp[2] << 8) | udp[3];
    udp[0] = (dst_port >> 8) & 0xFF;
    udp[1] = dst_port & 0xFF;
    udp[2] = (src_port >> 8) & 0xFF;
    udp[3] = src_port & 0xFF;

    // UDP checksum (необязательно для простого ответа, можно оставить 0)
    udp[6] = 0;
    udp[7] = 0;

    ssize_t w = write(tun_fd, reply, len);
    if (w < 0) perror("write(tun_fd UDP reply)");
    else printf("UDP: replied %zd bytes\n", w);
}
