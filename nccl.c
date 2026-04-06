/*
 * nccl.c — NCCL test orchestration
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Runs nccl-tests binaries (e.g. all_reduce_perf) as a subprocess via popen(),
 * parses their tabular output, and stores results for TUI correlation display.
 *
 * Expected output format (nccl-tests standard):
 *   #       size  count  type  redop    time  algbw  busbw  ...
 *   33554432  8388608  float  sum  820.5  40.89  76.67  N/A  ...
 */
#define _GNU_SOURCE
#include "nccl.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nccl_state nccl = {
    .status         = NCCL_IDLE,
    .binary         = "/usr/local/bin/all_reduce_perf",
    .args           = "-b 8 -e 256M -f 2 -g 1",
    .result_count   = 0,
    .baseline_bus_bw = 0.0,
};

static pthread_mutex_t nccl_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Parse a single data line from nccl-tests output.
 * Returns 1 on success, 0 if the line is not a data row.
 *
 * Data lines start with whitespace then a numeric size value.
 * Format: size count type redop time algbw busbw #wrong ...
 */
static int parse_nccl_line(const char *line, struct nccl_result *out) {
    /* Skip comment/header lines */
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
        return 0;

    /* First non-space token must be a decimal size */
    size_t   msg_size;
    unsigned long long count;
    char     type[16], redop[16];
    double   time_us, alg_bw, bus_bw;

    int n = sscanf(line, " %zu %llu %15s %15s %lf %lf %lf",
                   &msg_size, &count, type, redop, &time_us, &alg_bw, &bus_bw);
    if (n < 7)
        return 0;

    out->msg_size = msg_size;
    out->time_us  = time_us;
    out->alg_bw   = alg_bw;
    out->bus_bw   = bus_bw;
    return 1;
}

static void *nccl_run_thread(void *arg) {
    (void)arg;
    char cmd[NCCL_BINARY_MAX + NCCL_ARGS_MAX + 8];
    snprintf(cmd, sizeof(cmd), "%s %s 2>&1", nccl.binary, nccl.args);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        pthread_mutex_lock(&nccl_mutex);
        nccl.status = NCCL_ERROR;
        snprintf(nccl.last_error, sizeof(nccl.last_error), "popen failed");
        pthread_mutex_unlock(&nccl_mutex);
        return NULL;
    }

    char line[512];
    struct nccl_result results[NCCL_MAX_RESULTS];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (count >= NCCL_MAX_RESULTS)
            break;
        struct nccl_result r;
        if (parse_nccl_line(line, &r))
            results[count++] = r;
    }

    int rc = pclose(fp);

    pthread_mutex_lock(&nccl_mutex);
    if (rc != 0 && count == 0) {
        nccl.status = NCCL_ERROR;
        snprintf(nccl.last_error, sizeof(nccl.last_error),
                 "nccl-tests exited with code %d", rc);
    } else {
        memcpy(nccl.results, results, count * sizeof(results[0]));
        nccl.result_count = count;
        nccl.status = NCCL_DONE;
    }
    pthread_mutex_unlock(&nccl_mutex);

    return NULL;
}

void nccl_init(const char *binary) {
    if (binary)
        snprintf(nccl.binary, sizeof(nccl.binary), "%s", binary);
}

int nccl_launch(void) {
    pthread_mutex_lock(&nccl_mutex);
    if (nccl.status == NCCL_RUNNING) {
        pthread_mutex_unlock(&nccl_mutex);
        return -1; /* already running */
    }
    nccl.status = NCCL_RUNNING;
    nccl.result_count = 0;
    pthread_mutex_unlock(&nccl_mutex);

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&tid, &attr, nccl_run_thread, NULL);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        pthread_mutex_lock(&nccl_mutex);
        nccl.status = NCCL_ERROR;
        pthread_mutex_unlock(&nccl_mutex);
        return -1;
    }
    return 0;
}

void nccl_set_baseline(void) {
    pthread_mutex_lock(&nccl_mutex);
    /* Use the largest message size result as the representative busbw */
    double best = 0.0;
    for (int i = 0; i < nccl.result_count; i++) {
        if (nccl.results[i].bus_bw > best)
            best = nccl.results[i].bus_bw;
    }
    if (best > 0.0)
        nccl.baseline_bus_bw = best;
    pthread_mutex_unlock(&nccl_mutex);
}

void nccl_get_summary(char *buf, size_t len) {
    pthread_mutex_lock(&nccl_mutex);

    switch (nccl.status) {
    case NCCL_IDLE:
        snprintf(buf, len, "idle — press [n] to run test");
        break;
    case NCCL_RUNNING:
        snprintf(buf, len, "running...");
        break;
    case NCCL_ERROR:
        snprintf(buf, len, "error: %s", nccl.last_error);
        break;
    case NCCL_DONE: {
        /* Report the last (largest message) result */
        if (nccl.result_count == 0) {
            snprintf(buf, len, "done — no results parsed");
            break;
        }
        struct nccl_result *r = &nccl.results[nccl.result_count - 1];
        if (nccl.baseline_bus_bw > 0.0) {
            double delta = ((r->bus_bw - nccl.baseline_bus_bw) /
                            nccl.baseline_bus_bw) * 100.0;
            snprintf(buf, len,
                     "busbw: %.1f GB/s  baseline: %.1f GB/s  delta: %+.1f%%",
                     r->bus_bw, nccl.baseline_bus_bw, delta);
        } else {
            snprintf(buf, len,
                     "busbw: %.1f GB/s  algbw: %.1f GB/s  (%.0f us)",
                     r->bus_bw, r->alg_bw, r->time_us);
        }
        break;
    }
    }

    pthread_mutex_unlock(&nccl_mutex);
}
