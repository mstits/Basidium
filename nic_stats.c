/*
 * nic_stats.c — NIC statistics reader
 */
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

#else /* non-Linux stub */

int nic_stats_read(const char *iface, struct nic_stats *out) {
    (void)iface;
    memset(out, 0, sizeof(*out));
    return -1;
}

#endif /* __linux__ */
