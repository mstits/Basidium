/*
 * nccl.h — NCCL test orchestration and result tracking
 *
 * Launches nccl-tests binaries (all_reduce_perf, etc.) as subprocesses,
 * parses busbw output, and surfaces results to the TUI for correlation
 * with active flood/stress operations.
 */
#ifndef NCCL_MODULE_H
#define NCCL_MODULE_H

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

struct nccl_state {
    nccl_status_t    status;
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

#endif /* NCCL_MODULE_H */
