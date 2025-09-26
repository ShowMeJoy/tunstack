#include "tun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>       // struct ifreq, IFNAMSIZ
#include <linux/if_tun.h> // IFF_TUN, IFF_TAP, TUNSETIFF

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
    +-----------------+        read(fd)        +-----------------+
    |   Linux Kernel  | <--------------------> |   Your Program  |
    |  Network Stack  |                        |  (userspace)    |
    |-----------------|                        |-----------------|
    | - TCP/IP        |                        | - fd from open  |
    | - Routing       |                        | - read/write    | 
    | - ARP, ICMP     |                        | - parse packets |
    +-----------------+                        +-----------------+
            ^
            | ioctl(TUNSETIFF)
            | create interface
            |
    +-----------------+
    | /dev/net/tun    |
    |  (Device File)  |
    +-----------------+
*/
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        exit(1);
    }

    strcpy(dev, ifr.ifr_name);
    printf("TUN interface %s is ready\n", ifr.ifr_name);
    return fd;
}


