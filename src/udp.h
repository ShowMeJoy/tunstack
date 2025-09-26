#ifndef UDP_H
#define UDP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Проверяет, что это UDP-пакет
bool is_udp(const unsigned char *buf, size_t len);

// Печатает инфо о UDP-пакете
void handle_udp(const unsigned char *buf, size_t len);

#endif // UDP_H
