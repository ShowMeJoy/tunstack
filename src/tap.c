#include "tun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

int tap_alloc(char *dev) {
    struct ifreq ifr;
    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
    }
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) <0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        exit(1);
    }

    strcpy(dev, ifr.ifr_name);
    printf("TAP interface %s is ready\n", ifr.ifr_name);
    return fd;
}