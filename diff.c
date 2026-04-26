/*
 * diff.c — compare two Basidium JSON reports for regression detection.
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * The reports we emit have a known shape (sweep.steps[].pps_achieved,
 * sweep.steps[].nccl_busbw, scenario.steps[].{pps_achieved,nccl_busbw}).
 * Rather than pull in a JSON parser dependency we walk the file and
 * extract numeric values keyed by name in document order — sufficient
 * for the well-formed output write_report() produces, and we fail loudly
 * on hand-edited reports rather than silently misaligning.
 */
#define _GNU_SOURCE
#include "diff.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STEPS 256

struct step {
    long   pps_target;
    long   pps_achieved;
    double nccl_busbw;
    int    have_pps;
    int    have_nccl;
    char   mode[16];
};

struct parsed {
    struct step steps[MAX_STEPS];
    int         count;
    char        which[32];   /* "sweep" or "scenario" — for the header */
};

static char *slurp(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "diff: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0 || sz > 64 * 1024 * 1024) {
        fprintf(stderr, "diff: %s: implausible size %ld\n", path, sz);
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

/* Find the next occurrence of `key` followed by `:` and pull out a long.
 * Advances *cursor past the consumed value.  Returns 1 on hit, 0 on miss. */
static int find_long(char **cursor, const char *end, const char *key, long *out) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr(*cursor, needle);
    if (!p || p >= end) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (p < end && isspace((unsigned char)*p)) p++;
    char *e = NULL;
    long v = strtol(p, &e, 10);
    if (e == p) return 0;
    *out = v;
    *cursor = e;
    return 1;
}

static int find_double(char **cursor, const char *end, const char *key, double *out) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr(*cursor, needle);
    if (!p || p >= end) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (p < end && isspace((unsigned char)*p)) p++;
    char *e = NULL;
    double v = strtod(p, &e);
    if (e == p) return 0;
    *out = v;
    *cursor = e;
    return 1;
}

static int find_string(char **cursor, const char *end, const char *key,
                       char *out, size_t out_len) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr(*cursor, needle);
    if (!p || p >= end) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (p < end && isspace((unsigned char)*p)) p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (p < end && *p != '"' && i + 1 < out_len)
        out[i++] = *p++;
    out[i] = '\0';
    if (*p != '"') return 0;
    *cursor = p + 1;
    return 1;
}

/* Parse the sweep or scenario steps array out of a report.  We locate the
 * "steps": [ marker, then walk forward extracting one record per { ... }. */
static int parse_steps(char *json, struct parsed *out) {
    char *p = json;
    char *end = json + strlen(json);

    char *sweep = strstr(p, "\"sweep\"");
    char *scen  = strstr(p, "\"scenario\"");

    char *steps_anchor = NULL;
    if (sweep) {
        char *s = strstr(sweep, "\"steps\"");
        if (s && (!scen || s < scen)) {
            steps_anchor = s;
            snprintf(out->which, sizeof(out->which), "sweep");
        }
    }
    if (!steps_anchor && scen) {
        char *s = strstr(scen, "\"steps\"");
        if (s) {
            steps_anchor = s;
            snprintf(out->which, sizeof(out->which), "scenario");
        }
    }
    if (!steps_anchor) {
        fprintf(stderr, "diff: report has neither sweep nor scenario steps\n");
        return -1;
    }

    char *arr = strchr(steps_anchor, '[');
    if (!arr) return -1;
    arr++;

    int count = 0;
    char *cursor = arr;
    while (cursor < end && count < MAX_STEPS) {
        char *brace = strchr(cursor, '{');
        if (!brace) break;
        char *close = strchr(brace, '}');
        if (!close) break;

        char *step_cursor = brace;
        struct step *st = &out->steps[count];
        memset(st, 0, sizeof(*st));

        long pt = 0, pa = 0;
        if (find_long(&step_cursor, close, "pps_target", &pt))
            st->pps_target = pt;
        step_cursor = brace;
        if (find_long(&step_cursor, close, "pps_achieved", &pa)) {
            st->pps_achieved = pa;
            st->have_pps = 1;
        }
        step_cursor = brace;
        double bw = 0.0;
        if (find_double(&step_cursor, close, "nccl_busbw", &bw)) {
            st->nccl_busbw = bw;
            st->have_nccl = 1;
        }
        step_cursor = brace;
        find_string(&step_cursor, close, "mode", st->mode, sizeof(st->mode));

        count++;
        cursor = close + 1;
        if (*cursor == ']' || (*cursor && strchr("]", *cursor))) break;
    }
    out->count = count;
    return 0;
}

int diff_reports(const char *old_path, const char *new_path,
                 double pps_threshold_pct, double nccl_threshold_pct) {
    char *a = slurp(old_path);
    char *b = slurp(new_path);
    if (!a || !b) {
        free(a); free(b);
        return 1;
    }

    struct parsed pa = {0}, pb = {0};
    if (parse_steps(a, &pa) != 0 || parse_steps(b, &pb) != 0) {
        free(a); free(b);
        return 1;
    }

    if (strcmp(pa.which, pb.which) != 0)
        printf("note: report types differ (%s vs %s) — comparing in order\n",
               pa.which, pb.which);

    int n = pa.count < pb.count ? pa.count : pb.count;
    if (pa.count != pb.count)
        printf("note: step counts differ (%d vs %d) — comparing first %d\n",
               pa.count, pb.count, n);

    printf("\n%-5s %-6s %12s %12s %10s   %10s %10s %10s\n",
           "step", "mode", "old_pps", "new_pps", "Δpps%",
           "old_busbw", "new_busbw", "Δbusbw%");
    printf("%-5s %-6s %12s %12s %10s   %10s %10s %10s\n",
           "----", "----", "-------", "-------", "-----",
           "---------", "---------", "-------");

    int regressed = 0;
    for (int i = 0; i < n; i++) {
        struct step *sa = &pa.steps[i];
        struct step *sb = &pb.steps[i];
        const char *mode = sb->mode[0] ? sb->mode : sa->mode;
        if (!mode[0]) mode = "-";

        double dpps = 0.0;
        char dpps_str[16] = "-";
        if (sa->have_pps && sb->have_pps && sa->pps_achieved > 0) {
            dpps = (double)(sb->pps_achieved - sa->pps_achieved) /
                   (double)sa->pps_achieved * 100.0;
            snprintf(dpps_str, sizeof(dpps_str), "%+9.1f%%", dpps);
        }

        double dbw = 0.0;
        char dbw_str[16] = "-";
        char old_bw[16] = "-", new_bw[16] = "-";
        if (sa->have_nccl) snprintf(old_bw, sizeof(old_bw), "%9.2f", sa->nccl_busbw);
        if (sb->have_nccl) snprintf(new_bw, sizeof(new_bw), "%9.2f", sb->nccl_busbw);
        if (sa->have_nccl && sb->have_nccl && sa->nccl_busbw > 0.0) {
            dbw = (sb->nccl_busbw - sa->nccl_busbw) / sa->nccl_busbw * 100.0;
            snprintf(dbw_str, sizeof(dbw_str), "%+9.1f%%", dbw);
        }

        printf("%-5d %-6s %12ld %12ld %10s   %10s %10s %10s\n",
               i + 1, mode,
               sa->have_pps ? sa->pps_achieved : 0,
               sb->have_pps ? sb->pps_achieved : 0,
               dpps_str, old_bw, new_bw, dbw_str);

        if (pps_threshold_pct < 0.0 && sa->have_pps && sb->have_pps &&
                sa->pps_achieved > 0 && dpps <= pps_threshold_pct)
            regressed = 1;
        if (nccl_threshold_pct < 0.0 && sa->have_nccl && sb->have_nccl &&
                sa->nccl_busbw > 0.0 && dbw <= nccl_threshold_pct)
            regressed = 1;
    }

    printf("\n");
    if (regressed) {
        printf("REGRESSION: at least one step exceeded threshold "
               "(pps<=%.1f%%, busbw<=%.1f%%)\n",
               pps_threshold_pct, nccl_threshold_pct);
    } else {
        printf("OK: no step exceeded thresholds.\n");
    }

    free(a); free(b);
    return regressed ? 2 : 0;
}
