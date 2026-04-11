/*
 * tco.c — Targeted Congestion Orchestration
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Scenario file parser and orchestrator thread.
 * Steps through multi-mode congestion patterns with optional per-step
 * NCCL correlation measurements.
 */
#define _GNU_SOURCE
#include "tco.h"
#include "nccl.h"
#include "nic_stats.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- shared state definitions ---- */

struct tco_scenario     tco_scenario;
struct tco_step_result  tco_results[TCO_MAX_STEPS];
atomic_int              tco_current_step = 0;
atomic_int              tco_step_rem     = 0;

/* ---- scenario parser ---- */

int tco_load(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "tco: cannot open scenario: %s\n", path);
        return -1;
    }

    memset(&tco_scenario, 0, sizeof(tco_scenario));
    memset(tco_results,   0, sizeof(tco_results));

    /* Extract scenario name from filename (basename, strip extension) */
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    strncpy(tco_scenario.name, base, sizeof(tco_scenario.name) - 1);
    char *dot = strrchr(tco_scenario.name, '.');
    if (dot) *dot = '\0';

    char line[512];
    int lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;

        /* strip leading whitespace */
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;

        /* skip comments and blank lines */
        if (*p == '#' || *p == '\n' || *p == '\0')
            continue;

        if (tco_scenario.step_count >= TCO_MAX_STEPS) {
            fprintf(stderr, "tco: %s:%d: too many steps (max %d)\n",
                    path, lineno, TCO_MAX_STEPS);
            fclose(fp);
            return -1;
        }

        struct tco_step *step = &tco_scenario.steps[tco_scenario.step_count];
        char mode_str[16] = {0};
        char nccl_str[16] = {0};
        int pps = 0, dur = 0;

        int n = sscanf(p, "%15s %d %d %15s", mode_str, &pps, &dur, nccl_str);
        if (n < 3) {
            fprintf(stderr, "tco: %s:%d: expected: mode pps duration [nccl]\n",
                    path, lineno);
            fclose(fp);
            return -1;
        }

        step->mode = mode_from_string(mode_str);
        if (step->mode == MODE_INVALID) {
            fprintf(stderr, "tco: %s:%d: unknown mode '%s'\n",
                    path, lineno, mode_str);
            fclose(fp);
            return -1;
        }

        if (pps < 0) {
            fprintf(stderr, "tco: %s:%d: pps must be >= 0\n", path, lineno);
            fclose(fp);
            return -1;
        }

        if (dur <= 0) {
            fprintf(stderr, "tco: %s:%d: duration must be > 0\n", path, lineno);
            fclose(fp);
            return -1;
        }

        step->pps        = pps;
        step->duration_s = dur;
        step->run_nccl   = (n >= 4 && strcmp(nccl_str, "nccl") == 0) ? 1 : 0;

        tco_scenario.step_count++;
    }

    fclose(fp);

    if (tco_scenario.step_count == 0) {
        fprintf(stderr, "tco: %s: no steps found\n", path);
        return -1;
    }

    return 0;
}

/* ---- orchestrator thread ---- */

void *tco_thread_func(void *arg) {
    (void)arg;

    /* Wait for TUI user to start, or CLI mode starts immediately */
    while (!is_started && is_running)
        sleep(1);

    log_event("TCO_START", "Scenario started");

    for (int i = 0; i < tco_scenario.step_count && is_running; i++) {
        struct tco_step *step = &tco_scenario.steps[i];

        /* Apply this step's configuration */
        conf.mode = step->mode;
        conf.pps  = step->pps;
        atomic_store(&tco_current_step, i + 1);

        char msg[128];
        snprintf(msg, sizeof(msg), "step %d/%d mode=%s pps=%d dur=%ds%s",
                 i + 1, tco_scenario.step_count,
                 mode_to_string(step->mode), step->pps, step->duration_s,
                 step->run_nccl ? " +nccl" : "");
        log_event("TCO_STEP", msg);

        /* Launch NCCL test at the start of this step if requested */
        int nccl_launched = 0;
        if (step->run_nccl && conf.nccl) {
            if (nccl_launch() == 0) {
                nccl_launched = 1;
                log_event("TCO_NCCL", "NCCL test launched");
            } else {
                log_event("TCO_NCCL", "NCCL launch failed (busy or error)");
            }
        }

        /* Snapshot NIC stats at step start */
        struct nic_stats nic_before;
        int have_nic = (nic_stats_read(conf.interface, &nic_before) == 0);

        /* Hold at this mode/rate for the step duration */
        unsigned long long sent_start = (unsigned long long)total_sent;

        for (int t = step->duration_s; t > 0 && is_running; t--) {
            atomic_store(&tco_step_rem, t);
            sleep(1);
        }

        unsigned long long sent_end = (unsigned long long)total_sent;
        tco_results[i].achieved_pps = (step->duration_s > 0)
            ? (sent_end - sent_start) / step->duration_s
            : 0;

        /* Compute NIC stats delta for this step */
        if (have_nic) {
            struct nic_stats nic_after;
            if (nic_stats_read(conf.interface, &nic_after) == 0) {
                tco_results[i].nic_delta.tx_packets = nic_after.tx_packets - nic_before.tx_packets;
                tco_results[i].nic_delta.tx_bytes   = nic_after.tx_bytes   - nic_before.tx_bytes;
                tco_results[i].nic_delta.tx_dropped = nic_after.tx_dropped - nic_before.tx_dropped;
                tco_results[i].nic_delta.tx_errors  = nic_after.tx_errors  - nic_before.tx_errors;
                tco_results[i].nic_delta.rx_packets = nic_after.rx_packets - nic_before.rx_packets;
                tco_results[i].nic_delta.rx_bytes   = nic_after.rx_bytes   - nic_before.rx_bytes;
                tco_results[i].nic_valid = 1;
            }
        }

        /* Wait for NCCL to finish if launched */
        if (nccl_launched) {
            int nccl_wait = 300;
            while (nccl.status == NCCL_RUNNING && is_running && nccl_wait-- > 0) {
                atomic_store(&tco_step_rem, 0);
                sleep(1);
            }
            if (nccl.status == NCCL_DONE && nccl.result_count > 0) {
                tco_results[i].nccl_busbw =
                    nccl.results[nccl.result_count - 1].bus_bw;
                tco_results[i].nccl_valid = 1;

                /* Auto-set baseline from first successful measurement */
                if (nccl.baseline_bus_bw <= 0.0)
                    nccl_set_baseline();
            }
        }

        /* Log completed step */
        if (tco_results[i].nccl_valid && nccl.baseline_bus_bw > 0.0) {
            double delta = ((tco_results[i].nccl_busbw - nccl.baseline_bus_bw)
                            / nccl.baseline_bus_bw) * 100.0;
            snprintf(msg, sizeof(msg),
                     "step %d done: %llu pps  nccl=%.1f GB/s (%+.1f%%)",
                     i + 1, tco_results[i].achieved_pps,
                     tco_results[i].nccl_busbw, delta);
        } else {
            snprintf(msg, sizeof(msg), "step %d done: %llu pps",
                     i + 1, tco_results[i].achieved_pps);
        }
        log_event("TCO_STEP_DONE", msg);
    }

    log_event("TCO_DONE", "Scenario completed");
    atomic_store(&is_running, 0);
    return NULL;
}
