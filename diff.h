/*
 * diff.h — compare two Basidium JSON reports
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Reads two reports produced by --report and prints a step-by-step
 * comparison of achieved PPS and NCCL busbw.  Intended for regression
 * detection in CI ("did this firmware drop break us?") rather than
 * deep semantic analysis.
 */
#ifndef BASIDIUM_DIFF_H
#define BASIDIUM_DIFF_H

/*
 * Compare report `old_path` against `new_path`.  Writes a human-readable
 * report to stdout.  Returns 0 if no regressions exceed `pps_threshold_pct`
 * or `nccl_threshold_pct` (both negative-percent values; e.g. -10.0 means
 * "warn at 10% drop"), 2 if any threshold was breached, 1 on file-load
 * error.  Threshold of 0 disables that axis.
 */
int diff_reports(const char *old_path, const char *new_path,
                 double pps_threshold_pct, double nccl_threshold_pct);

#endif /* BASIDIUM_DIFF_H */
