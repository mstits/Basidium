/*
 * tco.h — Targeted Congestion Orchestration
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Scenario-driven congestion orchestration for GPU cluster fabric validation.
 * Defines multi-step congestion patterns with per-step mode, PPS, duration,
 * and optional NCCL correlation measurements.
 *
 * Scenario file format (.tco):
 *   # comment
 *   mode  pps  duration_s  [nccl]
 *
 * Example:
 *   mac   1000  30  nccl
 *   pfc   5000  60  nccl
 *   pfc  20000  60  nccl
 *   mac   1000  30  nccl
 */
#ifndef TCO_H
#define TCO_H

#include "flood.h"
#include "nic_stats.h"
#include <stdatomic.h>

#define TCO_MAX_STEPS      64
#define TCO_SCENARIO_MAX   256   /* max path length */

/* ---- scenario definition ---- */

struct tco_step {
    flood_mode_t mode;
    int          pps;
    int          duration_s;
    int          run_nccl;       /* 1 = launch NCCL test during this step */
};

struct tco_scenario {
    char             name[64];
    struct tco_step  steps[TCO_MAX_STEPS];
    int              step_count;
};

/* ---- per-step results ---- */

struct tco_step_result {
    unsigned long long achieved_pps;
    double             nccl_busbw;
    int                nccl_valid;
    struct nic_stats   nic_delta;    /* per-step tx/rx/drop delta */
    int                nic_valid;    /* 1 if nic_delta was computed */
};

/* ---- shared state (defined in tco.c) ---- */

extern struct tco_scenario     tco_scenario;
extern struct tco_step_result  tco_results[TCO_MAX_STEPS];
extern atomic_int              tco_current_step;   /* 1-indexed for display */
extern atomic_int              tco_step_rem;       /* seconds remaining */

/* ---- API ---- */

/*
 * Load a scenario from a .tco file.
 * Returns 0 on success, -1 on error (file not found, parse error, empty).
 * Prints diagnostic to stderr on error.
 */
int   tco_load(const char *path);

/*
 * Scenario orchestrator thread function.
 * Steps through the scenario, changing conf.mode and conf.pps at each step,
 * optionally launching NCCL tests, recording results.
 * Sets is_running=0 on completion.
 */
void *tco_thread_func(void *arg);

#endif /* TCO_H */
