/*
 * nic_stats.c — NIC statistics reader
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Linux:  reads from /sys/class/net/<iface>/statistics/
 * macOS:  reads from sysctl net.link.generic.system via getifaddrs + if_data
 * Other:  returns -1 (stub)
 */
#define _GNU_SOURCE
#include "nic_stats.h"

#include <stdio.h>
#include <string.h>

#ifdef __linux__

static int read_u64(const char *iface, const char *stat, uint64_t *out) {
    char path[256];
    snprintf(path, sizeof(path),
             "/sys/class/net/%s/statistics/%s", iface, stat);
    FILE *fp = fopen(path, "r");
    if (!fp) { *out = 0; return -1; }
    int rc = (fscanf(fp, "%llu", (unsigned long long *)out) == 1) ? 0 : -1;
    fclose(fp);
    return rc;
}

int nic_stats_read(const char *iface, struct nic_stats *out) {
    memset(out, 0, sizeof(*out));
    if (!iface || iface[0] == '\0') return -1;

    int r = 0;
    r |= read_u64(iface, "tx_packets", &out->tx_packets);
    r |= read_u64(iface, "tx_bytes",   &out->tx_bytes);
    r |= read_u64(iface, "tx_dropped", &out->tx_dropped);
    r |= read_u64(iface, "tx_errors",  &out->tx_errors);
    r |= read_u64(iface, "rx_packets", &out->rx_packets);
    r |= read_u64(iface, "rx_bytes",   &out->rx_bytes);
    return r ? -1 : 0;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

/* BSD / macOS: use getifaddrs() with AF_LINK to get interface statistics
 * from the if_data struct attached to each AF_LINK ifaddr entry. */

#ifdef __APPLE__
#include <net/if_dl.h>
#define IFA_DATA_CAST struct if_data *
#else
#include <net/if_dl.h>
#define IFA_DATA_CAST struct if_data *
#endif

int nic_stats_read(const char *iface, struct nic_stats *out) {
    memset(out, 0, sizeof(*out));
    if (!iface || iface[0] == '\0') return -1;

    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0)
        return -1;

    int found = 0;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        if (strcmp(ifa->ifa_name, iface) != 0) continue;
        if (ifa->ifa_data == NULL) continue;

        IFA_DATA_CAST ifd = (IFA_DATA_CAST)ifa->ifa_data;
        out->tx_packets = ifd->ifi_opackets;
        out->tx_bytes   = ifd->ifi_obytes;
        out->tx_dropped = ifd->ifi_oerrors;  /* closest BSD equivalent */
        out->tx_errors  = ifd->ifi_oerrors;
        out->rx_packets = ifd->ifi_ipackets;
        out->rx_bytes   = ifd->ifi_ibytes;
        found = 1;
        break;
    }

    freeifaddrs(ifap);
    return found ? 0 : -1;
}

#else /* unknown platform stub */

int nic_stats_read(const char *iface, struct nic_stats *out) {
    (void)iface;
    memset(out, 0, sizeof(*out));
    return -1;
}

#endif
