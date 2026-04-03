/*
 * report.c — JSON session report writer
 */
#include "report.h"
#include "flood.h"
#include "nccl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *mode_name(int mode) {
    switch (mode) {
    case 1:  return "arp";
    case 2:  return "dhcp";
    case 3:  return "pfc";
    case 4:  return "nd";
    case 5:  return "lldp";
    case 6:  return "stp";
    case 7:  return "igmp";
    default: return "mac";
    }
}

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
    fprintf(fp, "  \"mode\": \"%s\",\n", mode_name(conf.mode));
    fprintf(fp, "  \"threads\": %d,\n", conf.threads);

    if (conf.vlan_id > 0)
        fprintf(fp, "  \"vlan_id\": %d,\n  \"vlan_pcp\": %d,\n",
                conf.vlan_id, conf.vlan_pcp);

    if (conf.mode == 3)
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
        fprintf(fp, "    \"steps\": [\n");
        int pps = conf.sweep_start;
        for (int i = 0; i < nsteps; i++, pps += conf.sweep_step) {
            fprintf(fp, "      {\"pps_target\": %d, \"pps_achieved\": %llu}%s\n",
                    pps, sweep_step_pps[i],
                    (i < nsteps - 1) ? "," : "");
        }
        fprintf(fp, "    ]\n");
        fprintf(fp, "  },\n");
    } else {
        fprintf(fp, "  \"sweep\": null,\n");
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
