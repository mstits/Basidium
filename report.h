/*
 * report.h — session report writer
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Writes a JSON report at end-of-session capturing config, timing,
 * throughput, sweep results, NCCL busbw, and NIC error counters.
 */
#ifndef REPORT_H
#define REPORT_H

#include "nic_stats.h"

/*
 * Write a session report to `path` (creates or overwrites).
 * Pass NULL for `path` to auto-generate "basidium-YYYYMMDD-HHMMSS.json"
 * in the current directory.
 * `final_nic` may be NULL if NIC stats are unavailable.
 *
 * Returns 0 on success, -1 on failure. On failure an error is printed to
 * stderr and any partial file is removed so downstream tooling doesn't
 * consume half-written JSON.
 */
int write_report(const char *path, const struct nic_stats *final_nic);

#endif /* REPORT_H */
