/*
 * basidium.c v2.4
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
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "diff.h"

#ifndef BASIDIUM_VERSION
#define BASIDIUM_VERSION "2.5"
#endif

/*
 * Validated integer parsers.  atoi() and bare strtol() silently swallow
 * malformed input (returning 0 for "abc", truncating "10m" to 10) which has
 * caused profile-loader corruption and CLI-flag confusion.  These helpers
 * abort with a field-named error so the operator fixes the input instead of
 * running with a surprising value.
 */
static long parse_long_range(const char *s, long lo, long hi, const char *what) {
    if (!s || !*s) errx(1, "--%s: missing value", what);
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 0);
    if (errno == ERANGE)
        errx(1, "--%s: value '%s' out of range", what, s);
    if (end == s || *end != '\0')
        errx(1, "--%s: value '%s' is not an integer", what, s);
    if (v < lo || v > hi)
        errx(1, "--%s: value %ld out of range (%ld..%ld)", what, v, lo, hi);
    return v;
}

static int parse_int_range(const char *s, int lo, int hi, const char *what) {
    return (int)parse_long_range(s, lo, hi, what);
}

/* ---- Global state definitions (extern'd in flood.h) ---- */
struct config     conf;
atomic_ullong     total_sent      = 0;
volatile sig_atomic_t signal_stop = 0;
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

/* ---- Signal handler ----
 * Async-signal-safe: writes only a sig_atomic_t flag.  The main loop polls
 * signal_stop and propagates to is_running so workers exit cleanly.  Avoids
 * relying on atomic_store from a signal handler being lock-free, which is
 * implementation-defined per the C11 standard. */
static void handle_signal(int sig) {
    (void)sig;
    signal_stop = 1;
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    /* No SA_RESTART — we want sleep()/select() to return EINTR so the main
     * loop notices the stop flag promptly. */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Ignore SIGPIPE: popen()'d NCCL subprocess and per-event log fopens both
     * write through pipes that can disappear; the default action is to kill
     * the whole process, which we never want during a long-running test. */
    struct sigaction ign;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGPIPE, &ign, NULL);
}

static int color_enabled(void) {
    if (conf.no_color) return 0;
    const char *nc = getenv("NO_COLOR");
    if (nc && nc[0]) return 0;
    const char *term = getenv("TERM");
    if (term && strcmp(term, "dumb") == 0) return 0;
    return 1;
}

static void print_effective_config(void) {
    printf("# Basidium effective config\n");
    printf("interface=%s\n",         conf.interface ? conf.interface : "");
    printf("mode=%s\n",              mode_to_string(conf.mode));
    printf("threads=%d\n",           conf.threads);
    printf("pps=%d\n",               conf.pps);
    printf("count=%d\n",             conf.count);
    printf("packet_size=%d\n",       conf.packet_size);
    printf("session_duration=%d\n",  conf.session_duration);
    printf("vlan_id=%d\n",           conf.vlan_id);
    printf("vlan_pcp=%d\n",          conf.vlan_pcp);
    printf("vlan_range_end=%d\n",    conf.vlan_range_end);
    printf("qinq_outer_vid=%d\n",    conf.qinq_outer_vid);
    printf("pfc_priority=%d\n",      conf.pfc_priority);
    printf("pfc_quanta=%d\n",        conf.pfc_quanta);
    printf("stealth=%d\n",           conf.stealth);
    if (conf.stealth)
        printf("stealth_oui=%02x:%02x:%02x\n",
               conf.stealth_oui[0], conf.stealth_oui[1], conf.stealth_oui[2]);
    printf("learning=%d\n",          conf.learning);
    printf("adaptive=%d\n",          conf.adaptive);
    printf("allow_multicast=%d\n",   conf.allow_multicast);
    printf("random_client_mac=%d\n", conf.random_client_mac);
    printf("verbose=%d\n",           conf.verbose);
    printf("log_file=%s\n",          conf.log_file ? conf.log_file : "");
    printf("pcap_out_file=%s\n",     conf.pcap_out_file ? conf.pcap_out_file : "");
    printf("pcap_replay_file=%s\n",  conf.pcap_replay_file ? conf.pcap_replay_file : "");
    printf("report_path=%s\n",       conf.report_path ? conf.report_path : "");
    printf("payload_pattern=%d\n",   conf.payload_pattern);
    printf("burst_count=%d\n",       conf.burst_count);
    printf("burst_gap_ms=%d\n",      conf.burst_gap_ms);
    printf("detect_failopen=%d\n",   conf.detect_failopen);
    printf("nccl=%d\n",              conf.nccl);
    printf("scenario_file=%s\n",     conf.scenario_file ? conf.scenario_file : "");
    printf("target_count=%d\n",      conf.target_count);
    for (int i = 0; i < conf.target_count; i++) {
        struct in_addr a = { .s_addr = conf.targets[i].ip };
        /* The mask was stored in host order at parse time
         * (see -T case in main()), so no ntohl here. */
        int prefix = 0;
        uint32_t m = conf.targets[i].mask;
        while (m & 0x80000000u) { prefix++; m <<= 1; }
        printf("target[%d]=%s/%d\n", i, inet_ntoa(a), prefix);
    }
    printf("sweep_enabled=%d\n",     conf.sweep_enabled);
    if (conf.sweep_enabled) {
        printf("sweep_start=%d\n",   conf.sweep_start);
        printf("sweep_end=%d\n",     conf.sweep_end);
        printf("sweep_step=%d\n",    conf.sweep_step);
        printf("sweep_hold=%d\n",    conf.sweep_hold);
    }
    printf("stop_on_failopen=%d\n",  conf.stop_on_failopen);
    printf("stop_on_degradation_pct=%.2f\n", conf.stop_on_degradation_pct);
    printf("rng_seed=%llu\n",        (unsigned long long)conf.rng_seed);
    printf("ndjson=%d\n",            conf.ndjson);
    printf("report_compact=%d\n",    conf.report_compact);
    printf("csv_path=%s\n",          conf.csv_path ? conf.csv_path : "");
}

static void print_modes(void) {
    static const flood_mode_t all[] = {MODE_MAC,MODE_ARP,MODE_DHCP,MODE_PFC,
                                       MODE_ND,MODE_LLDP,MODE_STP,MODE_IGMP};
    for (size_t i = 0; i < sizeof(all)/sizeof(all[0]); i++)
        printf("%s\n", mode_to_string(all[i]));
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
    printf("  --duration <time>     Auto-stop after duration (e.g. 30, 5m, 2h, 1d)\n\n");

    printf("\033[1mBURST & ADVANCED:\033[0m\n");
    printf("  --burst <count:gap_ms>  Send <count> frames back-to-back then pause <gap_ms> ms\n");
    printf("  --detect                Fail-open detection: alert when switch echoes injected frames\n");
    printf("  --payload <pattern>     MAC flood payload fill: zeros ff dead incr (default: zeros)\n\n");

    printf("\033[1mSTOP CONDITIONS:\033[0m\n");
    printf("  --stop-on-failopen        Halt run on first fail-open detection (exit 2)\n");
    printf("  --stop-on-degradation N   Halt sweep/scenario when NCCL drops past -N%% (exit 2)\n\n");

    printf("\033[1mOUTPUT:\033[0m\n");
    printf("  --ndjson           One status object per line on stdout (machine-readable)\n");
    printf("  --csv <file>       Emit sweep/scenario steps as CSV in addition to --report\n");
    printf("  --report-compact   Single-line JSON report instead of pretty-printed\n\n");

    printf("\033[1mDIAGNOSTICS:\033[0m\n");
    printf("  --selftest        Run built-in validation suite (builders + parsers)\n");
    printf("  --validate <file> Validate a .tco scenario file and exit\n");
    printf("  --print-config    Print effective merged config as KV and exit\n");
    printf("  --list-modes      Print supported flood modes and exit\n");
    printf("  --list-profiles   Print saved profile names and exit\n");
    printf("  --diff a.json b.json   Compare two reports for regression and exit\n");
    printf("  --diff-threshold-pps N      pps regression threshold (default -10)\n");
    printf("  --diff-threshold-busbw N    NCCL busbw regression threshold (default -10)\n");
    printf("  --seed N          Seed RNG deterministically (default: OS entropy)\n");
    printf("  --version         Print version and exit (--version --json for JSON)\n");
    printf("  --dry-run         Build & count packets without injecting (no sudo needed)\n\n");

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
    printf("  sudo ./basidium -i eth0 --burst 64:100\n");
    printf("  basidium --diff baseline.json today.json\n\n");
}

static void usage_and_exit(int code) {
    usage();
    exit(code);
}

/* ---- Main ---- */
int main(int argc, char **argv) {
    /* RNG seed source — used for probe_signature now and for the worker
     * RNGs once we know whether --seed was passed. */
    rng_base_seed = entropy_seed();
    probe_signature = (uint16_t)(rng_base_seed & 0xFFFF);
    if (probe_signature == 0) probe_signature = 1;
    memset(&conf, 0, sizeof(conf));
    for (int i = 0; i < MAX_THREADS; i++)
        atomic_store(&thread_sent[i], 0);

    /* learned_macs is only used in -L learning mode.  Defer the 24KB
     * allocation until we know learning is enabled. */
    learned_macs = NULL;

    conf.threads      = 1;
    conf.pfc_priority = 3;
    conf.pfc_quanta   = 0xFFFF;
    conf.no_color     = !color_enabled();

    /* Subcommand-style entry: `basidium --diff a.json b.json` short-circuits
     * before getopt parsing so positional args work intuitively. */
    if (argc >= 2 && strcmp(argv[1], "--diff") == 0) {
        if (argc < 4) errx(1, "--diff: usage: basidium --diff old.json new.json "
                              "[--diff-threshold-pps N] [--diff-threshold-busbw N]");
        double thr_pps  = -10.0;
        double thr_busbw = -10.0;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--diff-threshold-pps") == 0 && i + 1 < argc) {
                thr_pps = strtod(argv[++i], NULL);
            } else if (strcmp(argv[i], "--diff-threshold-busbw") == 0 && i + 1 < argc) {
                thr_busbw = strtod(argv[++i], NULL);
            } else {
                errx(1, "--diff: unknown option '%s'", argv[i]);
            }
        }
        return diff_reports(argv[2], argv[3], thr_pps, thr_busbw);
    }

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
        /* v2.5 quick-win flags */
        {"validate",     required_argument, 0, 0},
        {"print-config", no_argument,       0, 0},
        {"list-modes",   no_argument,       0, 0},
        {"list-profiles",no_argument,       0, 0},
        {"seed",         required_argument, 0, 0},
        {"ndjson",       no_argument,       0, 0},
        {"csv",          required_argument, 0, 0},
        {"report-compact", no_argument,     0, 0},
        {"stop-on-failopen", no_argument,   0, 0},
        {"stop-on-degradation", required_argument, 0, 0},
        {"json",         no_argument,       0, 0},  /* modifies --version */
        {"help",         no_argument,       0, 0},
        {0, 0, 0, 0}
    };

    /* Deferred actions — these print and exit after option parsing so they see
     * any --profile / --print-config combination (e.g. show what a profile loads). */
    int want_print_config = 0;
    int want_list_modes   = 0;
    int want_list_profiles = 0;
    int version_json      = 0;
    int print_version     = 0;
    char *validate_path   = NULL;

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:M:t:r:J:LAS:T:l:vn:RUV:h",
                              long_options, &option_index)) != -1) {
        if (opt == 0) {
            const char *name = long_options[option_index].name;
            if (strcmp(name, "selftest")    == 0) { conf.self_test = 1; continue; }
            if (strcmp(name, "dry-run")     == 0) { conf.dry_run   = 1; continue; }
            if (strcmp(name, "pcap-out")    == 0) { conf.pcap_out_file    = strdup(optarg); continue; }
            if (strcmp(name, "pcap-replay") == 0) { conf.pcap_replay_file = strdup(optarg); continue; }
            if (strcmp(name, "tui")         == 0) { conf.tui = 1; continue; }
            if (strcmp(name, "nccl")        == 0) { conf.nccl = 1; continue; }
            if (strcmp(name, "nccl-binary") == 0) { conf.nccl = 1; nccl_init(optarg); continue; }
            if (strcmp(name, "profile")     == 0) {
                if (profiles_load(optarg, &conf) != 0)
                    errx(1, "failed to load profile '%s' — check ~/.basidium/%s.conf",
                         optarg, optarg);
                continue;
            }
            if (strcmp(name, "vlan-pcp")    == 0) {
                conf.vlan_pcp = parse_int_range(optarg, 0, 7, "vlan-pcp"); continue;
            }
            if (strcmp(name, "pfc-priority")== 0) {
                conf.pfc_priority = parse_int_range(optarg, 0, 7, "pfc-priority"); continue;
            }
            if (strcmp(name, "pfc-quanta")  == 0) {
                conf.pfc_quanta = parse_int_range(optarg, 0, 0xFFFF, "pfc-quanta"); continue;
            }
            if (strcmp(name, "report")      == 0) {
                conf.report_path = optarg ? strdup(optarg) : strdup("");
                continue;
            }
            if (strcmp(name, "version")     == 0) { print_version = 1; continue; }
            if (strcmp(name, "json")        == 0) { version_json = 1; continue; }
            if (strcmp(name, "help")        == 0) { usage_and_exit(0); }
            if (strcmp(name, "sweep")       == 0) {
                int a = 0, b = 0, c = 0, d = 10;
                int n = sscanf(optarg, "%d:%d:%d:%d", &a, &b, &c, &d);
                if (n < 3)
                    errx(1, "--sweep format: start:end:step[:hold_s]  e.g. 1000:50000:5000:10  (got '%s')", optarg);
                if (a <= 0 || b <= a || c <= 0)
                    errx(1, "--sweep: need start < end with positive step (got %d:%d:%d)", a, b, c);
                /* Guard against overflow when computing step count downstream. */
                if (b - a > c * MAX_SWEEP_STEPS)
                    errx(1, "--sweep: %d steps would exceed MAX_SWEEP_STEPS=%d — increase step",
                         (b - a) / c, MAX_SWEEP_STEPS);
                conf.sweep_enabled = 1;
                conf.sweep_start   = a;
                conf.sweep_end     = b;
                conf.sweep_step    = c;
                conf.sweep_hold    = (d > 0) ? d : 10;
                continue;
            }
            if (strcmp(name, "burst")       == 0) {
                int bc = 0, bg = 0;
                if (sscanf(optarg, "%d:%d", &bc, &bg) != 2 || bc <= 0 || bg < 0)
                    errx(1, "--burst format: count:gap_ms (got '%s')", optarg);
                conf.burst_count  = bc;
                conf.burst_gap_ms = bg;
                continue;
            }
            if (strcmp(name, "vlan-range")  == 0) {
                conf.vlan_range_end = parse_int_range(optarg, 1, 4094, "vlan-range"); continue;
            }
            if (strcmp(name, "detect")      == 0) { conf.detect_failopen = 1; continue; }
            if (strcmp(name, "payload")     == 0) {
                if      (strcmp(optarg, "zeros") == 0) conf.payload_pattern = 0;
                else if (strcmp(optarg, "ff")    == 0) conf.payload_pattern = 1;
                else if (strcmp(optarg, "dead")  == 0) conf.payload_pattern = 2;
                else if (strcmp(optarg, "incr")  == 0) conf.payload_pattern = 3;
                else errx(1, "--payload: unknown pattern '%s' (use: zeros|ff|dead|incr)", optarg);
                continue;
            }
            if (strcmp(name, "qinq")        == 0) {
                conf.qinq_outer_vid = parse_int_range(optarg, 1, 4094, "qinq"); continue;
            }
            if (strcmp(name, "duration")    == 0) {
                char *end = NULL;
                errno = 0;
                long val = strtol(optarg, &end, 10);
                if (end == optarg || val < 0 || errno == ERANGE)
                    errx(1, "--duration: '%s' is not a valid duration", optarg);
                if      (*end == '\0' || *end == 's') {}
                else if (*end == 'm' && end[1] == '\0') val *= 60;
                else if (*end == 'h' && end[1] == '\0') val *= 3600;
                else if (*end == 'd' && end[1] == '\0') val *= 86400;
                else errx(1, "--duration: unknown suffix '%s' (use s/m/h/d)", end);
                if (val > INT_MAX) errx(1, "--duration: %ld too large", val);
                conf.session_duration = (int)val;
                continue;
            }
            if (strcmp(name, "scenario")    == 0) {
                conf.scenario_file = strdup(optarg); continue;
            }
            if (strcmp(name, "validate")    == 0) {
                validate_path = strdup(optarg); continue;
            }
            if (strcmp(name, "print-config")  == 0) { want_print_config  = 1; continue; }
            if (strcmp(name, "list-modes")    == 0) { want_list_modes    = 1; continue; }
            if (strcmp(name, "list-profiles") == 0) { want_list_profiles = 1; continue; }
            if (strcmp(name, "seed")          == 0) {
                errno = 0;
                char *endp = NULL;
                conf.rng_seed = strtoull(optarg, &endp, 0);
                if (endp == optarg || (endp && *endp != '\0') || errno == ERANGE)
                    errx(1, "--seed: '%s' is not a valid 64-bit integer", optarg);
                conf.seed_set = 1;
                continue;
            }
            if (strcmp(name, "ndjson")          == 0) { conf.ndjson = 1; continue; }
            if (strcmp(name, "csv")             == 0) { conf.csv_path = strdup(optarg); continue; }
            if (strcmp(name, "report-compact")  == 0) { conf.report_compact = 1; continue; }
            if (strcmp(name, "stop-on-failopen")== 0) { conf.stop_on_failopen = 1;
                                                         conf.detect_failopen = 1; continue; }
            if (strcmp(name, "stop-on-degradation") == 0) {
                errno = 0;
                char *endp = NULL;
                double v = strtod(optarg, &endp);
                if (endp == optarg || errno == ERANGE)
                    errx(1, "--stop-on-degradation: '%s' is not a number", optarg);
                /* Operator may say "30" or "-30" — both mean "stop at 30% drop". */
                if (v > 0) v = -v;
                conf.stop_on_degradation_pct = v;
                continue;
            }
            continue;
        }
        switch (opt) {
        case 'i': conf.interface        = strdup(optarg);  break;
        case 'V':
            conf.vlan_id = parse_int_range(optarg, 0, 4094, "V (vlan)");
            break;
        case 'M':
            conf.mode = mode_from_string(optarg);
            if (conf.mode == MODE_INVALID)
                errx(1, "Unknown mode '%s' — valid: mac arp dhcp pfc nd lldp stp igmp", optarg);
            break;
        case 't': conf.threads     = parse_int_range(optarg, 1, MAX_THREADS, "t (threads)"); break;
        case 'r': conf.pps         = parse_int_range(optarg, 0, INT_MAX, "r (pps)"); break;
        case 'n': conf.count       = parse_int_range(optarg, 0, INT_MAX, "n (count)"); break;
        case 'J': conf.packet_size = parse_int_range(optarg, 60, MAX_PACKET_SIZE, "J (frame size)"); break;
        case 'L': conf.learning         = 1;            break;
        case 'A': conf.adaptive         = 1;            break;
        case 'R': conf.random_client_mac = 1;           break;
        case 'U': conf.allow_multicast  = 1;            break;
        case 'v': conf.verbose          = 1;            break;
        case 'l': conf.log_file         = strdup(optarg); break;
        case 'h': usage_and_exit(0);                       break;
        case 'S': {
            unsigned int a, b, c;
            if (sscanf(optarg, "%x:%x:%x", &a, &b, &c) != 3 ||
                a > 0xFF || b > 0xFF || c > 0xFF)
                errx(1, "-S OUI: '%s' must be three hex bytes (e.g. 00:11:22)", optarg);
            conf.stealth = 1;
            conf.stealth_oui[0] = (uint8_t)a;
            conf.stealth_oui[1] = (uint8_t)b;
            conf.stealth_oui[2] = (uint8_t)c;
            break;
        }
        case 'T': {
            if (conf.target_count >= MAX_TARGETS)
                errx(1, "-T: too many targets (max %d)", MAX_TARGETS);
            char ip_str[32] = {0};
            int mask_bits = -1;
            if (sscanf(optarg, "%31[^/]/%d", ip_str, &mask_bits) != 2 ||
                mask_bits < 0 || mask_bits > 32)
                errx(1, "-T: '%s' must be CIDR (e.g. 10.0.0.0/24)", optarg);
            uint32_t ipv = inet_addr(ip_str);
            if (ipv == INADDR_NONE)
                errx(1, "-T: '%s' has invalid IP", optarg);
            conf.targets[conf.target_count].ip = ipv;
            conf.targets[conf.target_count].mask =
                (mask_bits == 0) ? 0u : (uint32_t)(0xFFFFFFFFu << (32 - mask_bits));
            conf.target_count++;
            break;
        }
        default:
            usage_and_exit(2);
        }
    }

    /* Apply --seed now that parsing is done.  When --seed is set we replace
     * the entropy-derived rng_base_seed and recompute probe_signature so the
     * MAC-flood IP IDs are also deterministic — useful for `--diff` runs that
     * compare against a baseline. */
    if (conf.seed_set) {
        rng_base_seed = conf.rng_seed;
        probe_signature = (uint16_t)((rng_base_seed * 0x9E3779B97F4A7C15ULL) & 0xFFFF);
        if (probe_signature == 0) probe_signature = 1;
    }

    if (print_version) {
        if (version_json)
            printf("{\"version\": \"%s\"}\n", BASIDIUM_VERSION);
        else
            printf("Basidium v%s\n", BASIDIUM_VERSION);
        exit(0);
    }
    if (want_list_modes) { print_modes(); exit(0); }
    if (want_list_profiles) {
        char names[PROFILE_LIST_MAX][PROFILE_NAME_MAX];
        int n = profiles_list(names);
        for (int i = 0; i < n; i++) printf("%s\n", names[i]);
        exit(0);
    }
    if (validate_path) {
        int rc = tco_load(validate_path);
        if (rc == 0)
            printf("OK: %s — %d step%s\n", validate_path,
                   tco_scenario.step_count,
                   tco_scenario.step_count == 1 ? "" : "s");
        free(validate_path);
        exit(rc == 0 ? 0 : 1);
    }
    if (want_print_config) {
        print_effective_config();
        exit(0);
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
        if (!conf.ndjson)
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
        if (!conf.ndjson)
            printf("PCAP output mode: writing to %s\n", conf.pcap_out_file);
    }

    if (!conf.interface && !conf.dry_run) usage_and_exit(2);
    if (conf.threads < 1 || conf.threads > MAX_THREADS)
        errx(1, "Thread count must be 1-%d (got %d)", MAX_THREADS, conf.threads);

    /* Allocate learning ring only if it will actually be used.  Saves a
     * 24KB allocation that was leaked on every error-path exit before. */
    if (conf.learning) {
        learned_macs = malloc(MAX_LEARNED_MACS * 6);
        if (!learned_macs) errx(1, "malloc failed for learned_macs");
    }

    install_signals();
    start_time = time(NULL);
    log_event("START", "Stress test started");

    /* Start sniffer if learning or adaptive mode requested */
    pthread_t sniff_th;
    int sniff_running = 0;
    if (conf.learning || conf.adaptive || conf.detect_failopen) {
        int rc = pthread_create(&sniff_th, NULL, sniffer_thread_func, NULL);
        if (rc != 0)
            errx(1, "failed to start sniffer thread: %s", strerror(rc));
        sniff_running = 1;
        if (!conf.tui && !conf.ndjson)
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
        int rc = pthread_create(&sweep_th, NULL, sweep_thread_func, NULL);
        if (rc != 0)
            errx(1, "failed to start sweep thread: %s", strerror(rc));
        sweep_running = 1;
        if (!conf.tui && !conf.ndjson)
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
        int rc = pthread_create(&tco_th, NULL, tco_thread_func, NULL);
        if (rc != 0)
            errx(1, "failed to start TCO thread: %s", strerror(rc));
        tco_running = 1;
        if (!conf.tui && !conf.ndjson)
            printf("TCO scenario: %s (%d steps)%s\n",
                   tco_scenario.name, tco_scenario.step_count,
                   conf.nccl ? " [NCCL correlation active]" : "");
    }

    /* PCAP replay mode */
    pthread_t replay_th;
    int replay_running = 0;

    if (conf.pcap_replay_file) {
        int rc = pthread_create(&replay_th, NULL, pcap_replay_func, NULL);
        if (rc != 0)
            errx(1, "failed to start replay thread: %s", strerror(rc));
        replay_running = 1;
        if (!conf.tui && !conf.ndjson)
            printf("Replaying: %s\n", conf.pcap_replay_file);
    } else {
        for (int i = 0; i < conf.threads; i++) {
            thread_ids[i] = i;
            if (conf.verbose && !conf.tui && !conf.ndjson)
                printf("[thread %d] starting\n", i);
            int rc = pthread_create(&workers[i], NULL, worker_func, &thread_ids[i]);
            if (rc != 0)
                errx(1, "failed to start worker thread %d: %s", i, strerror(rc));
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
            if (signal_stop) atomic_store(&is_running, 0);
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
        /* CLI status loop.  --ndjson emits one JSON object per second to
         * stdout instead of the in-place spinner — useful for tee/jq/Loki. */
        unsigned long long last_sent = 0;
        while (is_running) {
            if (signal_stop) atomic_store(&is_running, 0);
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
            if (conf.ndjson) {
                printf("{\"ts\": %ld, \"total\": %llu, \"pps\": %llu, "
                       "\"mode\": \"%s\", \"failopen\": %d}\n",
                       (long)time(NULL), now_sent, pps_now,
                       mode_to_string(conf.mode),
                       (int)fail_open_detected);
            } else if (conf.verbose) {
                printf("\r[Total: %llu | PPS: %llu]   ", now_sent, pps_now);
            } else {
                printf("\r[Total: %llu]   ", now_sent);
            }
            last_sent = now_sent;
            fflush(stdout);
        }
        if (!conf.ndjson) printf("\n");
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
    if (!conf.ndjson)
        printf("Done. Total sent: %llu  Peak PPS: %llu\n",
               (unsigned long long)total_sent,
               (unsigned long long)peak_pps);

    /* session report */
    if (conf.report_path || conf.sweep_enabled || conf.nccl || conf.scenario_file) {
        struct nic_stats final_nic;
        int have_nic = (nic_stats_read(conf.interface, &final_nic) == 0);
        write_report(conf.report_path, have_nic ? &final_nic : NULL);
    }
    if (conf.csv_path)
        write_csv(conf.csv_path);

    free(learned_macs);

    /* Exit 2 if fail-open was detected (scriptable for SRE alerting) */
    if (conf.detect_failopen && fail_open_detected)
        return 2;

    return 0;
}
