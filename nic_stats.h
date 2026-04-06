/*
 * nic_stats.h — NIC-level TX/RX counters
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Linux: reads from /sys/class/net/. macOS/BSD: getifaddrs() + AF_LINK if_data.
 * On unsupported platforms, nic_stats_read() returns -1 and zeroes all fields.
 */
#ifndef NIC_STATS_H
#define NIC_STATS_H

#include <stdint.h>

struct nic_stats {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_dropped;
    uint64_t tx_errors;
    uint64_t rx_packets;
    uint64_t rx_bytes;
};

/*
 * Populate `out` from /sys/class/net/<iface>/statistics/.
 * Returns 0 on success, -1 if unavailable (non-Linux, bad iface, no perms).
 */
int nic_stats_read(const char *iface, struct nic_stats *out);

#endif /* NIC_STATS_H */
