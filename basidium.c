/*
 * basidium.c v2.3
 * Basidium — Advanced Multi-Threaded Layer-2 Stress / Hardware Evaluation Utility
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * Author:  Matthew Stits <stits@stits.org>
 * GitHub:  https://github.com/mstits/Basidium
 *
 * Compile: make            (CLI only)
 *          make TUI=1      (with ncurses TUI — requires libncurses)
 */
#define _GNU_SOURCE
#include "flood.h"
#include "nccl.h"
#include "tco.h"
#include "profiles.h"
#include "nic_stats.h"
#include "report.h"
#ifdef HAVE_TUI
#include "tui.h"
#include <ncurses.h>
#endif

#include <arpa/inet.h>
#include <err.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef BASIDIUM_VERSION
#define BASIDIUM_VERSION "2.3"
#endif

/* ---- Global state definitions (extern'd in flood.h) ---- */
struct config     conf;
atomic_ullong     total_sent      = 0;
atomic_int        is_running           = 1;
atomic_int        is_paused            = 0;
atomic_int        is_started           = 0;
atomic_ullong     peak_pps             = 0;
atomic_int        sweep_step_num       = 0;
atomic_int        sweep_total_steps    = 0;
atomic_int        sweep_hold_rem       = 0;
unsigned long long sweep_step_pps[MAX_SWEEP_STEPS];
double             sweep_step_nccl_busbw[MAX_SWEEP_STEPS];
int                sweep_step_nccl_valid[MAX_SWEEP_STEPS];
struct nic_stats   sweep_step_nic_delta[MAX_SWEEP_STEPS];
int                sweep_step_nic_valid[MAX_SWEEP_STEPS];
atomic_ullong     thread_sent[MAX_THREADS];
atomic_ullong     bcast_rx        = 0;
uint16_t          probe_signature = 0;
atomic_int        fail_open_detected = 0;
uint8_t         (*learned_macs)[6] = NULL;
int               learned_count   = 0;
pcap_dumper_t    *global_pd       = NULL;
pthread_mutex_t   log_mutex       = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t   learn_mutex     = PTHREAD_MUTEX_INITIALIZER;
time_t            start_time      = 0;

/* ---- Signal handler ---- */
static void handle_signal(int sig) {
    (void)sig;
    atomic_store(&is_running, 0);
}

/* ---- Usage ---- */
static void usage(void) {
    printf("\n\033[1mBasidium v%s\033[0m - \033[36mLayer-2 Hardware Stress & Evaluation Tool\033[0m\n",
           BASIDIUM_VERSION);
    printf("================================================================\n\n");

    printf("\033[1mUSAGE:\033[0m\n");
    printf("  sudo ./basidium -i <interface> [options]\n\n");

    printf("\033[1mFLOOD MODES (-M):\033[0m\n");
    printf("  \033[32mmac\033[0m    Standard MAC flood — fills CAM tables (default)\n");
    printf("  \033[32marp\033[0m    Gratuitous ARP broadcast flood\n");
    printf("  \033[32mdhcp\033[0m   DHCP Discover starvation flood\n");
    printf("  \033[32mpfc\033[0m    802.1Qbb PFC PAUSE flood (RoCE/RDMA fabric testing)\n");
    printf("  \033[32mnd\033[0m     IPv6 Neighbor Discovery flood (ICMPv6 NS)\n");
    printf("  \033[32mlldp\033[0m   LLDP frame flood (stresses switch CPU / LLDP table)\n");
    printf("  \033[32mstp\033[0m    STP TCN BPDU flood (forces periodic MAC table flush)\n");
    printf("  \033[32migmp\033[0m   IGMPv2 Membership Report flood (exhausts IGMP snooping table)\n\n");

    printf("\033[1mVLAN & PFC OPTIONS:\033[0m\n");
    printf("  -V <id>              802.1Q VLAN tag (1-4094); applies to mac/arp/dhcp modes\n");
    printf("  --vlan-pcp <0-7>     802.1p priority bits in VLAN tag (default: 0)\n");
    printf("  --vlan-range <end>   Cycle VLAN IDs from -V <start> to <end> (random per frame)\n");
    printf("  --qinq <outer-vid>   802.1ad QinQ outer tag (combined with -V for true double-tag)\n");
    printf("  --pfc-priority <0-7> Priority class to pause in PFC mode (default: 3 = RDMA)\n");
    printf("  --pfc-quanta <val>   PFC pause quanta 0-65535 (default: 65535 = max)\n\n");

    printf("\033[1mINTERFACE & PERFORMANCE:\033[0m\n");
    printf("  -i <iface>   Network interface (required)\n");
    printf("  -t <num>     Worker threads (default: 1, max: %d)\n", MAX_THREADS);
    printf("  -r <pps>     Rate limit in packets/sec (0 = unlimited)\n");
    printf("  -J <bytes>   Frame size 60-%d bytes (jumbo frame support)\n", MAX_PACKET_SIZE);
    printf("  -n <count>   Stop after N packets\n\n");

    printf("\033[1mSTEALTH & TARGETING:\033[0m\n");
    printf("  -S <oui>     Stealth OUI prefix (e.g. 00:11:22)\n");
    printf("  -T <cidr>    Target IP subnet (e.g. 10.0.0.0/24)\n");
    printf("  -L           Learning mode — sniff real MACs, skip them\n");
    printf("  -A           Adaptive mode — throttle on fail-open detection\n");
    printf("  -U           Allow multicast source MACs\n");
    printf("  -R           Randomize DHCP client MAC independently\n\n");

    printf("\033[1mOUTPUT & LOGGING:\033[0m\n");
    printf("  -v              Verbose: per-thread startup and live PPS\n");
    printf("  -l <file>       JSON event log file\n");
    printf("  --tui           Interactive ncurses TUI (iptraf-ng style)\n");
    printf("  --report [file] Write JSON session report on exit\n");
    printf("                  Default filename: basidium_report_<timestamp>.json\n\n");

    printf("\033[1mRATE SWEEP:\033[0m\n");
    printf("  --sweep <start:end:step[:hold_s]>  Ramp rate from start to end pps\n");
    printf("                                     step    increment per stage (pps)\n");
    printf("                                     hold_s  seconds per stage (default: 10)\n");
    printf("  With --nccl: auto-measures NCCL busbw at each step for correlation.\n");
    printf("  Tip: pair --sweep with --report to produce a full benchmark JSON report.\n\n");

    printf("\033[1mTCO (TARGETED CONGESTION ORCHESTRATION):\033[0m\n");
    printf("  --scenario <file.tco>  Run a multi-step congestion scenario\n");
    printf("                         Each line: mode  pps  duration_s  [nccl]\n");
    printf("                         Switches modes at runtime across workers.\n");
    printf("                         Mutually exclusive with --sweep.\n\n");

    printf("\033[1mNETWORK I/O:\033[0m\n");
    printf("  --pcap-out <file>     Write packets to .pcap instead of live inject\n");
    printf("  --pcap-replay <file>  Replay .pcap frames onto the interface\n\n");

    printf("\033[1mNCCL CORRELATION:\033[0m\n");
    printf("  --nccl                Enable NCCL busbw correlation (TUI + sweep + scenario)\n");
    printf("  --nccl-binary <path>  Path to nccl-tests binary (implies --nccl)\n\n");

    printf("\033[1mPROFILES & SESSIONS:\033[0m\n");
    printf("  --profile <name>      Load named profile from ~/.basidium/<name>.conf\n");
    printf("  --duration <time>     Auto-stop after duration (e.g. 30, 5m, 2h)\n\n");

    printf("\033[1mBURST & ADVANCED:\033[0m\n");
    printf("  --burst <count:gap_ms>  Send <count> frames back-to-back then pause <gap_ms> ms\n");
    printf("  --detect                Fail-open detection: alert when switch echoes injected frames\n");
    printf("  --payload <pattern>     MAC flood payload fill: zeros ff dead incr (default: zeros)\n\n");

    printf("\033[1mDIAGNOSTICS:\033[0m\n");
    printf("  --selftest   Run built-in packet builder validation suite\n");
    printf("  --version    Print version and exit\n");
    printf("  --dry-run    Build & count packets without injecting (no sudo needed)\n\n");

    printf("\033[1mEXAMPLES:\033[0m\n");
    printf("  sudo ./basidium -i eth0 -t 4\n");
    printf("  sudo ./basidium -i eth0 -M arp -r 5000 --tui\n");
    printf("  sudo ./basidium -i eth0 -S 00:03:93 -A -L\n");
    printf("  sudo ./basidium -i eth0 --pcap-replay capture.pcap\n");
    printf("  sudo ./basidium -i eth0 -V 10 --vlan-range 20 -t 4\n");
    printf("  sudo ./basidium -i eth0 --sweep 1000:50000:5000:10 --report\n");
    printf("  sudo ./basidium -i eth0 --sweep 1000:50000:5000:30 --nccl --report\n");
    printf("  sudo ./basidium -i eth0 --scenario scenario.tco --nccl --report\n");
    printf("  sudo ./basidium -i eth0 --detect -A\n");
    printf("  sudo ./basidium -i eth0 --burst 64:100\n\n");

    exit(1);
}

/* ---- Main ---- */
int main(int argc, char **argv) {
    srand(time(NULL));
    probe_signature = (uint16_t)(rand() & 0xFFFF);
    memset(&conf, 0, sizeof(conf));
    for (int i = 0; i < MAX_THREADS; i++)
        atomic_store(&thread_sent[i], 0);

    learned_macs = malloc(MAX_LEARNED_MACS * 6);
    if (!learned_macs)
        errx(1, "malloc failed");

    conf.threads      = 1;
    conf.pfc_priority = 3;
    conf.pfc_quanta   = 0xFFFF;

    static struct option long_options[] = {
        {"selftest",     no_argument,       0, 0},
        {"pcap-out",     required_argument, 0, 0},
        {"pcap-replay",  required_argument, 0, 0},
        {"tui",          no_argument,       0, 0},
        {"nccl",         no_argument,       0, 0},
        {"nccl-binary",  required_argument, 0, 0},
        {"duration",     required_argument, 0, 0},
        {"profile",      required_argument, 0, 0},
        {"vlan-pcp",     required_argument, 0, 0},
        {"pfc-priority", required_argument, 0, 0},
        {"pfc-quanta",   required_argument, 0, 0},
        {"sweep",        required_argument, 0, 0},
        {"report",       optional_argument, 0, 0},
        {"burst",        required_argument, 0, 0},
        {"vlan-range",   required_argument, 0, 0},
        {"detect",       no_argument,       0, 0},
        {"qinq",         required_argument, 0, 0},
        {"payload",      required_argument, 0, 0},
        {"version",      no_argument,       0, 0},
        {"dry-run",      no_argument,       0, 0},
        {"scenario",     required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:M:t:r:J:LAS:T:l:vn:RUV:",
                              long_options, &option_index)) != -1) {
        if (opt == 0) {
            const char *name = long_options[option_index].name;
            if (strcmp(name, "selftest")    == 0) conf.self_test      = 1;
            if (strcmp(name, "dry-run")     == 0) conf.dry_run        = 1;
            if (strcmp(name, "pcap-out")    == 0) conf.pcap_out_file  = strdup(optarg);
            if (strcmp(name, "pcap-replay") == 0) conf.pcap_replay_file = strdup(optarg);
            if (strcmp(name, "tui")         == 0) conf.tui            = 1;
            if (strcmp(name, "nccl")        == 0) conf.nccl           = 1;
            if (strcmp(name, "nccl-binary") == 0) { conf.nccl = 1; nccl_init(optarg); }
            if (strcmp(name, "profile")     == 0) profiles_load(optarg, &conf);
            if (strcmp(name, "vlan-pcp")    == 0) conf.vlan_pcp      = atoi(optarg) & 0x7;
            if (strcmp(name, "pfc-priority")== 0) conf.pfc_priority  = atoi(optarg) & 0x7;
            if (strcmp(name, "pfc-quanta")  == 0) conf.pfc_quanta    = (int)strtol(optarg, NULL, 0);
            if (strcmp(name, "report")      == 0) conf.report_path   = optarg ? strdup(optarg) : strdup("");
            if (strcmp(name, "version")     == 0) {
                printf("Basidium v%s\n", BASIDIUM_VERSION);
                exit(0);
            }
            if (strcmp(name, "sweep")       == 0) {
                int a = 0, b = 0, c = 0, d = 10;
                int n = sscanf(optarg, "%d:%d:%d:%d", &a, &b, &c, &d);
                if (n < 3)
                    errx(1, "--sweep format: start:end:step[:hold_s]  e.g. 1000:50000:5000:10");
                if (a <= 0 || b <= a || c <= 0)
                    errx(1, "--sweep: need start < end with positive step");
                conf.sweep_enabled = 1;
                conf.sweep_start   = a;
                conf.sweep_end     = b;
                conf.sweep_step    = c;
                conf.sweep_hold    = (d > 0) ? d : 10;
            }
            if (strcmp(name, "burst")       == 0) {
                int bc = 0, bg = 0;
                if (sscanf(optarg, "%d:%d", &bc, &bg) < 2 || bc <= 0 || bg < 0)
                    errx(1, "--burst format: count:gap_ms  e.g. 64:100");
                conf.burst_count  = bc;
                conf.burst_gap_ms = bg;
            }
            if (strcmp(name, "vlan-range")  == 0) {
                conf.vlan_range_end = atoi(optarg);
                if (conf.vlan_range_end < 1 || conf.vlan_range_end > 4094)
                    errx(1, "--vlan-range: end VID must be 1-4094");
            }
            if (strcmp(name, "detect")      == 0) conf.detect_failopen = 1;
            if (strcmp(name, "payload")     == 0) {
                conf.payload_pattern =
                    (strcmp(optarg, "ff")   == 0) ? 1 :
                    (strcmp(optarg, "dead") == 0) ? 2 :
                    (strcmp(optarg, "incr") == 0) ? 3 : 0;
            }
            if (strcmp(name, "qinq")        == 0) {
                conf.qinq_outer_vid = atoi(optarg);
                if (conf.qinq_outer_vid < 1 || conf.qinq_outer_vid > 4094)
                    errx(1, "--qinq: outer VID must be 1-4094");
            }
            if (strcmp(name, "duration")    == 0) {
                char *end;
                int val = (int)strtol(optarg, &end, 10);
                if      (*end == 'm') val *= 60;
                else if (*end == 'h') val *= 3600;
                conf.session_duration = val;
            }
            if (strcmp(name, "scenario")    == 0) {
                conf.scenario_file = strdup(optarg);
            }
            continue;
        }
        switch (opt) {
        case 'i': conf.interface        = strdup(optarg);  break;
        case 'V':
            conf.vlan_id = atoi(optarg);
            if (conf.vlan_id < 0 || conf.vlan_id > 4094)
                errx(1, "VLAN ID must be 0-4094");
            break;
        case 'M':
            conf.mode = mode_from_string(optarg);
            if (conf.mode == MODE_INVALID)
                errx(1, "Unknown mode '%s' — valid: mac arp dhcp pfc nd lldp stp igmp", optarg);
            break;
        case 't': conf.threads          = atoi(optarg); break;
        case 'r': conf.pps              = atoi(optarg); break;
        case 'n': conf.count            = atoi(optarg); break;
        case 'J': conf.packet_size      = atoi(optarg); break;
        case 'L': conf.learning         = 1;            break;
        case 'A': conf.adaptive         = 1;            break;
        case 'R': conf.random_client_mac = 1;           break;
        case 'U': conf.allow_multicast  = 1;            break;
        case 'v': conf.verbose          = 1;            break;
        case 'l': conf.log_file         = strdup(optarg); break;
        case 'S': {
            conf.stealth = 1;
            unsigned int a, b, c;
            if (sscanf(optarg, "%x:%x:%x", &a, &b, &c) == 3) {
                conf.stealth_oui[0] = (uint8_t)(a & 0xFF);
                conf.stealth_oui[1] = (uint8_t)(b & 0xFF);
                conf.stealth_oui[2] = (uint8_t)(c & 0xFF);
            }
            break;
        }
        case 'T':
            if (conf.target_count < MAX_TARGETS) {
                char ip_str[32];
                int mask_bits;
                sscanf(optarg, "%[^/]/%d", ip_str, &mask_bits);
                conf.targets[conf.target_count].ip =
                    inet_addr(ip_str);
                conf.targets[conf.target_count].mask =
                    (uint32_t)(0xFFFFFFFF << (32 - mask_bits));
                conf.target_count++;
            }
            break;
        default:
            usage();
        }
    }

    if (conf.self_test)
        exit(run_selftest());

#ifndef HAVE_TUI
    if (conf.tui) {
        fprintf(stderr, "Error: built without TUI support. Recompile with: make TUI=1\n");
        exit(1);
    }
#endif

    /* Dry-run mode: use pcap_open_dead, no interface required, no sudo */
    if (conf.dry_run) {
        pcap_t *dead = pcap_open_dead(DLT_EN10MB, MAX_PACKET_SIZE);
        if (!dead) errx(1, "pcap_open_dead failed");
        global_pd = pcap_dump_open(dead, "/dev/null");
        if (!global_pd) errx(1, "pcap_dump_open /dev/null failed");
        conf.threads = 1;
        if (!conf.interface) conf.interface = "dry-run";
        printf("Dry-run mode: building packets, no injection\n");
    }

    /* PCAP output mode */
    if (conf.pcap_out_file && !conf.dry_run) {
        pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
        if (!dead) errx(1, "pcap_open_dead failed");
        global_pd = pcap_dump_open(dead, conf.pcap_out_file);
        if (!global_pd) errx(1, "Cannot open pcap output: %s", conf.pcap_out_file);
        conf.threads = 1;
        if (!conf.interface) conf.interface = "pcap-writer";
        printf("PCAP output mode: writing to %s\n", conf.pcap_out_file);
    }

    if (!conf.interface && !conf.dry_run) usage();
    if (conf.threads < 1 || conf.threads > MAX_THREADS)
        errx(1, "Thread count must be 1-%d", MAX_THREADS);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    start_time = time(NULL);
    log_event("START", "Stress test started");

    /* Start sniffer if learning or adaptive mode requested */
    pthread_t sniff_th;
    int sniff_running = 0;
    if (conf.learning || conf.adaptive || conf.detect_failopen) {
        pthread_create(&sniff_th, NULL, sniffer_thread_func, NULL);
        sniff_running = 1;
        if (!conf.tui)
            printf("Sniffer running (learning=%d adaptive=%d detect=%d)\n",
                   conf.learning, conf.adaptive, conf.detect_failopen);
        sleep(1);
    }

    /* CLI mode starts immediately; TUI mode waits for user keypress */
    if (!conf.tui)
        atomic_store(&is_started, 1);

    /* Spawn worker threads */
    pthread_t workers[MAX_THREADS];
    int thread_ids[MAX_THREADS];

    /* Rate sweep thread */
    pthread_t sweep_th;
    int sweep_running = 0;
    if (conf.sweep_enabled && !conf.scenario_file) {
        conf.pps = conf.sweep_start;
        pthread_create(&sweep_th, NULL, sweep_thread_func, NULL);
        sweep_running = 1;
        if (!conf.tui)
            printf("Sweep: %d→%d pps, step %d, hold %ds%s\n",
                   conf.sweep_start, conf.sweep_end,
                   conf.sweep_step, conf.sweep_hold,
                   conf.nccl ? " [NCCL correlation active]" : "");
    }

    /* TCO scenario thread (mutually exclusive with sweep) */
    pthread_t tco_th;
    int tco_running = 0;
    if (conf.scenario_file) {
        if (conf.sweep_enabled) {
            fprintf(stderr, "Error: --scenario and --sweep are mutually exclusive\n");
            exit(1);
        }
        if (tco_load(conf.scenario_file) != 0)
            exit(1);
        pthread_create(&tco_th, NULL, tco_thread_func, NULL);
        tco_running = 1;
        if (!conf.tui)
            printf("TCO scenario: %s (%d steps)%s\n",
                   tco_scenario.name, tco_scenario.step_count,
                   conf.nccl ? " [NCCL correlation active]" : "");
    }

    /* PCAP replay mode */
    pthread_t replay_th;
    int replay_running = 0;

    if (conf.pcap_replay_file) {
        pthread_create(&replay_th, NULL, pcap_replay_func, NULL);
        replay_running = 1;
        if (!conf.tui)
            printf("Replaying: %s\n", conf.pcap_replay_file);
    } else {
        for (int i = 0; i < conf.threads; i++) {
            thread_ids[i] = i;
            if (conf.verbose && !conf.tui)
                printf("[thread %d] starting\n", i);
            pthread_create(&workers[i], NULL, worker_func, &thread_ids[i]);
        }
    }

    /* ---- Main loop ---- */
#ifdef HAVE_TUI
    if (conf.tui) {
        tui_init();
        tui_log("Started %s on %s (%d thread%s)",
                mode_to_string(conf.mode), conf.interface, conf.threads,
                conf.threads == 1 ? "" : "s");

        while (is_running) {
            if (conf.count > 0 &&
                (unsigned long long)total_sent >= (unsigned long long)conf.count) {
                atomic_store(&is_running, 0);
                break;
            }
            /* Session duration auto-stop — now enforced in TUI mode */
            if (conf.session_duration > 0 && is_started &&
                (time(NULL) - start_time) >= conf.session_duration) {
                tui_log("Session timer expired (%ds)", conf.session_duration);
                atomic_store(&is_running, 0);
                break;
            }
            int ch = getch();
            if (ch != ERR && tui_input(ch))
                atomic_store(&is_running, 0);
            tui_draw();
            usleep(100000);
        }
        tui_cleanup();
    } else
#endif
    {
        /* CLI status loop */
        unsigned long long last_sent = 0;
        while (is_running) {
            if (conf.count > 0 &&
                (unsigned long long)total_sent >= (unsigned long long)conf.count) {
                atomic_store(&is_running, 0);
                break;
            }
            if (conf.session_duration > 0 &&
                (time(NULL) - start_time) >= conf.session_duration) {
                atomic_store(&is_running, 0);
                break;
            }
            sleep(1);
            unsigned long long now_sent = (unsigned long long)total_sent;
            unsigned long long pps_now  = now_sent - last_sent;
            if (pps_now > (unsigned long long)peak_pps)
                atomic_store(&peak_pps, pps_now);
            if (conf.verbose)
                printf("\r[Total: %llu | PPS: %llu]   ", now_sent, pps_now);
            else
                printf("\r[Total: %llu]   ", now_sent);
            last_sent = now_sent;
            fflush(stdout);
        }
        printf("\n");
    }

    /* Cleanup */
    if (conf.pcap_replay_file && replay_running)
        pthread_join(replay_th, NULL);
    else
        for (int i = 0; i < conf.threads; i++)
            pthread_join(workers[i], NULL);

    if (sniff_running) {
        atomic_store(&is_running, 0);
        pthread_join(sniff_th, NULL);
    }

    if (sweep_running)
        pthread_join(sweep_th, NULL);

    if (tco_running)
        pthread_join(tco_th, NULL);

    if (global_pd) pcap_dump_close(global_pd);

    log_event("STOP", "Stress test finished");
    printf("Done. Total sent: %llu  Peak PPS: %llu\n",
           (unsigned long long)total_sent,
           (unsigned long long)peak_pps);

    /* session report */
    if (conf.report_path || conf.sweep_enabled || conf.nccl || conf.scenario_file) {
        struct nic_stats final_nic;
        int have_nic = (nic_stats_read(conf.interface, &final_nic) == 0);
        write_report(conf.report_path, have_nic ? &final_nic : NULL);
    }

    free(learned_macs);

    /* Exit 2 if fail-open was detected (scriptable for SRE alerting) */
    if (conf.detect_failopen && fail_open_detected)
        return 2;

    return 0;
}
