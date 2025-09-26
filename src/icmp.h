#ifndef ICMP_H
#define ICMP_H

#include <stdbool.h>
#include <stddef.h>

bool is_icmp(unsigned char *buf, size_t len);
void handle_icmp(unsigned char *buf, size_t len, int tun_fd);

#endif