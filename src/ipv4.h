#ifndef IPV4_H
#define IPV4_H

#include <stddef.h>
#include <stdbool.h>

bool is_ipv4(unsigned char *buf, size_t len);
void parse_ipv4(unsigned char *buf, size_t len);

#endif