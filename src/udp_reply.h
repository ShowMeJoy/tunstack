#ifndef UDP_REPLY_H
#define UDP_REPLY_H

#include <stddef.h>
#include <stdint.h>

void handle_udp_reply(const unsigned char *buf, size_t len, int tun_fd);

#endif // UDP_REPLY_H
