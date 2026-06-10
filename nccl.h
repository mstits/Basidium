/*
 * nccl.h — NCCL test orchestration and result tracking
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Launches nccl-tests binaries (all_reduce_perf, etc.) as subprocesses,
 * parses busbw output, and surfaces results to the TUI for correlation
 * with active flood/stress operations.
 *
 * NOTE: NCCL-tests require Linux + NVIDIA GPUs with CUDA. On macOS/BSD
 * the --nccl flag is accepted and the module compiles, but nccl_launch()
 * fails gracefully if the binary is not found (execvp in the child exits
 * 127 and the parent reports NCCL_ERROR).
 */
#ifndef NCCL_MODULE_H
#define NCCL_MODULE_H

#include <stdatomic.h>
#include <stddef.h>

#define NCCL_MAX_RESULTS 16
#define NCCL_BINARY_MAX  256
#define NCCL_ARGS_MAX    512

typedef enum {
    NCCL_IDLE,
    NCCL_RUNNING,
    NCCL_DONE,
    NCCL_ERROR,
} nccl_status_t;

struct nccl_result {
    size_t   msg_size;       /* message size in bytes */
    double   alg_bw;         /* algorithm bandwidth GB/s */
    double   bus_bw;         /* bus bandwidth GB/s */
    double   time_us;        /* avg time in microseconds */
};

/*
 * Concurrency invariant: `status` is _Atomic and is the publication point
 * for the result-array writes.  The producer (nccl_run_thread) writes
 * results[] and result_count, then stores status = NCCL_DONE.  Consumers
 * (sweep/TCO/TUI/report) read status atomically; if they observe DONE,
 * the prior result-array writes are guaranteed visible (seq_cst on the
 * status store implies release semantics, and seq_cst on the consumer's
 * load implies acquire — together they pair correctly even on weak-memory
 * archs like ARM where v2.5's plain-int status read could race).
 */
struct nccl_state {
    _Atomic nccl_status_t status;
    char             binary[NCCL_BINARY_MAX];    /* path to nccl-tests binary */
    char             args[NCCL_ARGS_MAX];         /* extra args */
    struct nccl_result results[NCCL_MAX_RESULTS];
    int              result_count;
    double           baseline_bus_bw;             /* set on first run, or manually */
    char             last_error[256];
};

/* Shared nccl state — defined in nccl.c */
extern struct nccl_state nccl;

void  nccl_init(const char *binary);
int   nccl_launch(void);              /* spawns background thread, returns 0 on success */
void  nccl_set_baseline(void);        /* stores current bus_bw as baseline */
void  nccl_get_summary(char *buf, size_t len); /* formatted one-line summary for TUI */

/* Exposed for selftest: parses one nccl-tests output line (1=data row, 0=skip). */
int   nccl_parse_line(const char *line, struct nccl_result *out);

#endif /* NCCL_MODULE_H */
