/*
 * report.c — JSON session report writer
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 */
#define _GNU_SOURCE
#include "report.h"
#include "flood.h"
#include "nccl.h"
#include "tco.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void write_esc(FILE *fp, const char *s) {
    /* minimal JSON string escaping */
    fputc('"', fp);
    for (; *s; s++) {
        if      (*s == '"')  fputs("\\\"", fp);
        else if (*s == '\\') fputs("\\\\", fp);
        else if (*s == '\n') fputs("\\n",  fp);
        else                 fputc(*s, fp);
    }
    fputc('"', fp);
}

void write_report(const char *path, const struct nic_stats *final_nic) {
    /* auto-generate filename if none specified */
    char auto_path[64];
    if (!path || path[0] == '\0') {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        strftime(auto_path, sizeof(auto_path),
                 "basidium-%Y%m%d-%H%M%S.json", tm);
        path = auto_path;
    }

    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "report: cannot open %s for writing\n", path);
        return;
    }

    time_t now      = time(NULL);
    time_t elapsed  = (now > start_time) ? (now - start_time) : 0;

    char ts[32];
    struct tm *tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);

    fprintf(fp, "{\n");
    fprintf(fp, "  \"generated\": \"%s\",\n", ts);
    fprintf(fp, "  \"interface\": ");
    write_esc(fp, conf.interface ? conf.interface : "");
    fprintf(fp, ",\n");
    fprintf(fp, "  \"mode\": \"%s\",\n", mode_to_string(conf.mode));
    fprintf(fp, "  \"threads\": %d,\n", conf.threads);

    if (conf.vlan_id > 0)
        fprintf(fp, "  \"vlan_id\": %d,\n  \"vlan_pcp\": %d,\n",
                conf.vlan_id, conf.vlan_pcp);

    if (conf.mode == MODE_PFC)
        fprintf(fp, "  \"pfc_priority\": %d,\n  \"pfc_quanta\": %d,\n",
                conf.pfc_priority, conf.pfc_quanta);

    fprintf(fp, "  \"pps_target\": %d,\n", conf.pps);
    fprintf(fp, "  \"packet_size\": %d,\n",
            conf.packet_size > 0 ? conf.packet_size : 64);

    /* timing */
    fprintf(fp, "  \"duration_s\": %ld,\n", (long)elapsed);
    fprintf(fp, "  \"total_packets\": %llu,\n",
            (unsigned long long)total_sent);
    fprintf(fp, "  \"peak_pps\": %llu,\n",
            (unsigned long long)peak_pps);

    /* rate sweep results */
    int nsteps = (int)sweep_total_steps;
    if (conf.sweep_enabled && nsteps > 0) {
        fprintf(fp, "  \"sweep\": {\n");
        fprintf(fp, "    \"start\": %d,\n",   conf.sweep_start);
        fprintf(fp, "    \"end\": %d,\n",     conf.sweep_end);
        fprintf(fp, "    \"step\": %d,\n",    conf.sweep_step);
        fprintf(fp, "    \"hold_s\": %d,\n",  conf.sweep_hold);
        if (conf.nccl && nccl.baseline_bus_bw > 0.0)
            fprintf(fp, "    \"nccl_baseline_busbw\": %.2f,\n",
                    nccl.baseline_bus_bw);
        fprintf(fp, "    \"steps\": [\n");
        int pps = conf.sweep_start;
        for (int i = 0; i < nsteps; i++, pps += conf.sweep_step) {
            fprintf(fp, "      {\"pps_target\": %d, \"pps_achieved\": %llu",
                    pps, sweep_step_pps[i]);
            if (sweep_step_nccl_valid[i]) {
                fprintf(fp, ", \"nccl_busbw\": %.2f",
                        sweep_step_nccl_busbw[i]);
                if (nccl.baseline_bus_bw > 0.0) {
                    double delta = ((sweep_step_nccl_busbw[i]
                                     - nccl.baseline_bus_bw)
                                    / nccl.baseline_bus_bw) * 100.0;
                    fprintf(fp, ", \"nccl_degradation_pct\": %.1f", delta);
                }
            }
            if (sweep_step_nic_valid[i]) {
                fprintf(fp, ", \"nic_delta\": {"
                        "\"tx_packets\": %llu, \"tx_bytes\": %llu, "
                        "\"tx_dropped\": %llu, \"tx_errors\": %llu}",
                        (unsigned long long)sweep_step_nic_delta[i].tx_packets,
                        (unsigned long long)sweep_step_nic_delta[i].tx_bytes,
                        (unsigned long long)sweep_step_nic_delta[i].tx_dropped,
                        (unsigned long long)sweep_step_nic_delta[i].tx_errors);
            }
            fprintf(fp, "}%s\n", (i < nsteps - 1) ? "," : "");
        }
        fprintf(fp, "    ]\n");
        fprintf(fp, "  },\n");
    } else {
        fprintf(fp, "  \"sweep\": null,\n");
    }

    /* TCO scenario results */
    if (conf.scenario_file && tco_scenario.step_count > 0) {
        fprintf(fp, "  \"scenario\": {\n");
        fprintf(fp, "    \"name\": ");
        write_esc(fp, tco_scenario.name);
        fprintf(fp, ",\n");
        fprintf(fp, "    \"file\": ");
        write_esc(fp, conf.scenario_file);
        fprintf(fp, ",\n");
        if (conf.nccl && nccl.baseline_bus_bw > 0.0)
            fprintf(fp, "    \"nccl_baseline_busbw\": %.2f,\n",
                    nccl.baseline_bus_bw);
        fprintf(fp, "    \"steps\": [\n");
        for (int i = 0; i < tco_scenario.step_count; i++) {
            struct tco_step *st = &tco_scenario.steps[i];
            fprintf(fp, "      {\"mode\": \"%s\", \"pps_target\": %d, "
                    "\"duration_s\": %d, \"pps_achieved\": %llu",
                    mode_to_string(st->mode), st->pps, st->duration_s,
                    tco_results[i].achieved_pps);
            if (tco_results[i].nccl_valid) {
                fprintf(fp, ", \"nccl_busbw\": %.2f",
                        tco_results[i].nccl_busbw);
                if (nccl.baseline_bus_bw > 0.0) {
                    double delta = ((tco_results[i].nccl_busbw
                                     - nccl.baseline_bus_bw)
                                    / nccl.baseline_bus_bw) * 100.0;
                    fprintf(fp, ", \"nccl_degradation_pct\": %.1f", delta);
                }
            }
            if (tco_results[i].nic_valid) {
                fprintf(fp, ", \"nic_delta\": {"
                        "\"tx_packets\": %llu, \"tx_bytes\": %llu, "
                        "\"tx_dropped\": %llu, \"tx_errors\": %llu}",
                        (unsigned long long)tco_results[i].nic_delta.tx_packets,
                        (unsigned long long)tco_results[i].nic_delta.tx_bytes,
                        (unsigned long long)tco_results[i].nic_delta.tx_dropped,
                        (unsigned long long)tco_results[i].nic_delta.tx_errors);
            }
            fprintf(fp, "}%s\n",
                    (i < tco_scenario.step_count - 1) ? "," : "");
        }
        fprintf(fp, "    ]\n");
        fprintf(fp, "  },\n");
    } else {
        fprintf(fp, "  \"scenario\": null,\n");
    }

    /* NCCL correlation */
    if (conf.nccl) {
        char summary[256];
        nccl_get_summary(summary, sizeof(summary));
        fprintf(fp, "  \"nccl\": {\n");
        fprintf(fp, "    \"binary\": ");
        write_esc(fp, nccl.binary);
        fprintf(fp, ",\n");
        if (nccl.result_count > 0) {
            struct nccl_result *r = &nccl.results[nccl.result_count - 1];
            fprintf(fp, "    \"last_busbw_gbps\": %.2f,\n", r->bus_bw);
            fprintf(fp, "    \"last_algbw_gbps\": %.2f,\n", r->alg_bw);
        }
        if (nccl.baseline_bus_bw > 0.0) {
            fprintf(fp, "    \"baseline_busbw_gbps\": %.2f,\n",
                    nccl.baseline_bus_bw);
            if (nccl.result_count > 0) {
                double delta = ((nccl.results[nccl.result_count-1].bus_bw
                                 - nccl.baseline_bus_bw)
                                / nccl.baseline_bus_bw) * 100.0;
                fprintf(fp, "    \"degradation_pct\": %.1f,\n", delta);
            }
        }
        fprintf(fp, "    \"runs\": %d\n", nccl.result_count);
        fprintf(fp, "  },\n");
    } else {
        fprintf(fp, "  \"nccl\": null,\n");
    }

    /* NIC statistics */
    if (final_nic) {
        fprintf(fp, "  \"nic_stats\": {\n");
        fprintf(fp, "    \"tx_packets\": %llu,\n",
                (unsigned long long)final_nic->tx_packets);
        fprintf(fp, "    \"tx_bytes\": %llu,\n",
                (unsigned long long)final_nic->tx_bytes);
        fprintf(fp, "    \"tx_dropped\": %llu,\n",
                (unsigned long long)final_nic->tx_dropped);
        fprintf(fp, "    \"tx_errors\": %llu\n",
                (unsigned long long)final_nic->tx_errors);
        fprintf(fp, "  }\n");
    } else {
        fprintf(fp, "  \"nic_stats\": null\n");
    }

    fprintf(fp, "}\n");
    fclose(fp);

    printf("Report written to: %s\n", path);
}
