/*
 * nic_stats.h — NIC-level TX/RX counters via /sys/class/net (Linux)
 *
 * On non-Linux systems, nic_stats_read() returns -1 and zeroes all fields.
 * Check the return value before displaying stats in the TUI.
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
