/*
 * tui.c — ncurses TUI for Basidium
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 *
 * iptraf-ng inspired panel layout with live statistics:
 *   - Live stats: PPS, total, uptime, session countdown
 *   - ASCII sparkline: 50-sample rolling PPS history
 *   - Per-thread PPS breakdown
 *   - NCCL correlation panel (only with --nccl)
 *   - Scrolling event log
 *   - Named profile save/load menu
 *   - Full-screen help overlay
 */
#ifdef HAVE_TUI

#define _GNU_SOURCE
#include "tui.h"
#include "flood.h"
#include "nccl.h"
#include "profiles.h"
#include "nic_stats.h"

#include <ncurses.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- color pairs ---- */
#define CP_HEADER  1   /* cyan on black   */
#define CP_GOOD    2   /* green on black  */
#define CP_WARN    3   /* yellow on black */
#define CP_ALERT   4   /* red on black    */
#define CP_DIM     5   /* white on black  */
#define CP_HILIGHT 6   /* black on cyan   */

/* ---- layout ---- */
#define HEADER_H     3
#define STATS_H      11  /* stats + sparkline + thread rows + NIC stats */
#define NCCL_PANEL_H 4
#define KEYS_H       2

static int tui_rows, tui_cols;

/* ---- windows ---- */
static WINDOW *w_header;
static WINDOW *w_stats;
static WINDOW *w_config;
static WINDOW *w_nccl;
static WINDOW *w_log;
static WINDOW *w_keys;

/* ---- log ring buffer ---- */
#define LOG_LINES    256
#define LOG_LINE_MAX 256

static char            log_ring[LOG_LINES][LOG_LINE_MAX];
static int             log_head  = 0;
static int             log_count = 0;
static pthread_mutex_t log_ring_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---- sparkline ---- */
#define SPARKLINE_LEN 50
static const char *spark_chars[] = {" ","▁","▂","▃","▄","▅","▆","▇","█"};
static unsigned long long spark_buf[SPARKLINE_LEN];
static int                spark_pos  = 0;
static int                spark_fill = 0;
static unsigned long long spark_max  = 1;

/* ---- per-thread PPS ---- */
static unsigned long long thread_last_sent[MAX_THREADS];
static unsigned long long thread_cur_pps[MAX_THREADS];

/* ---- NIC stats ---- */
static struct nic_stats nic_prev;
static struct nic_stats nic_cur;
static int              nic_available = 0;

/* ---- PPS state ---- */
static unsigned long long last_total = 0;
static time_t             last_tick  = 0;
static unsigned long long cur_pps    = 0;

/* ---- overlay state ---- */
static int show_disclaimer = 0;
static int show_help       = 0;
static int show_profiles   = 0;
static int show_intro      = 0;
static int intro_page      = 0;
#define INTRO_PAGES 4
static int profile_cursor  = 0;
static char profile_names[PROFILE_LIST_MAX][PROFILE_NAME_MAX];
static int  profile_count = 0;

/* ================================================================
 * Helpers
 * ================================================================ */

static void recreate_windows(void) {
    getmaxyx(stdscr, tui_rows, tui_cols);

    int nccl_h  = conf.nccl ? NCCL_PANEL_H : 0;
    int log_h   = tui_rows - HEADER_H - STATS_H - nccl_h - KEYS_H;
    if (log_h < 3) log_h = 3;

    int stats_w  = tui_cols / 2;
    int config_w = tui_cols - stats_w;

    if (w_header) delwin(w_header);
    if (w_stats)  delwin(w_stats);
    if (w_config) delwin(w_config);
    if (w_nccl)   { delwin(w_nccl); w_nccl = NULL; }
    if (w_log)    delwin(w_log);
    if (w_keys)   delwin(w_keys);

    int nccl_top = HEADER_H + STATS_H;
    int log_top  = nccl_top + nccl_h;

    w_header = newwin(HEADER_H, tui_cols, 0,        0);
    w_stats  = newwin(STATS_H,  stats_w,  HEADER_H, 0);
    w_config = newwin(STATS_H,  config_w, HEADER_H, stats_w);
    if (conf.nccl)
        w_nccl = newwin(NCCL_PANEL_H, tui_cols, nccl_top, 0);
    w_log    = newwin(log_h,    tui_cols, log_top,  0);
    w_keys   = newwin(KEYS_H,   tui_cols, tui_rows - KEYS_H, 0);

    wbkgd(w_header, COLOR_PAIR(CP_HEADER));
    wbkgd(w_stats,  COLOR_PAIR(CP_DIM));
    wbkgd(w_config, COLOR_PAIR(CP_DIM));
    wbkgd(w_log,    COLOR_PAIR(CP_DIM));
    wbkgd(w_keys,   COLOR_PAIR(CP_HILIGHT));
    if (w_nccl) wbkgd(w_nccl, COLOR_PAIR(CP_DIM));
}

static void update_per_second(void) {
    time_t now = time(NULL);
    if (now == last_tick) return;

    unsigned long long cur_total = (unsigned long long)total_sent;
    cur_pps    = cur_total - last_total;
    last_total = cur_total;
    last_tick  = now;

    /* sparkline */
    spark_buf[spark_pos % SPARKLINE_LEN] = cur_pps;
    spark_pos++;
    if (spark_fill < SPARKLINE_LEN) spark_fill++;

    /* recalculate max for scaling */
    spark_max = 1;
    for (int i = 0; i < spark_fill; i++) {
        if (spark_buf[i] > spark_max) spark_max = spark_buf[i];
    }

    /* per-thread PPS */
    for (int i = 0; i < conf.threads; i++) {
        unsigned long long cur = (unsigned long long)thread_sent[i];
        thread_cur_pps[i]      = cur - thread_last_sent[i];
        thread_last_sent[i]    = cur;
    }

    /* NIC stats delta */
    nic_prev      = nic_cur;
    nic_available = (nic_stats_read(conf.interface, &nic_cur) == 0);

    /* track peak PPS */
    if (cur_pps > (unsigned long long)peak_pps)
        atomic_store(&peak_pps, cur_pps);
}

static void draw_sparkline(WINDOW *w, int row, int col, int width) {
    if (width < 4) return;
    int w2 = width - 2; /* leave 1 char margin each side */
    if (w2 > SPARKLINE_LEN) w2 = SPARKLINE_LEN;

    /* grab the last w2 samples */
    wattron(w, COLOR_PAIR(CP_GOOD));
    for (int i = 0; i < w2; i++) {
        int idx = (spark_pos - w2 + i + SPARKLINE_LEN * 4) % SPARKLINE_LEN;
        if (i >= spark_fill) {
            mvwprintw(w, row, col + i, " ");
            continue;
        }
        unsigned long long v = spark_buf[idx];
        int level = (int)((v * 8) / spark_max);
        if (level > 8) level = 8;
        mvwprintw(w, row, col + i, "%s", spark_chars[level]);
    }
    wattroff(w, COLOR_PAIR(CP_GOOD));
}

/* ================================================================
 * Public: tui_log
 * ================================================================ */

void tui_log(const char *fmt, ...) {
    char msg[LOG_LINE_MAX];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[12];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    char line[LOG_LINE_MAX];
    snprintf(line, sizeof(line), "[%s] %s", ts, msg);

    pthread_mutex_lock(&log_ring_mutex);
    strncpy(log_ring[log_head % LOG_LINES], line, LOG_LINE_MAX - 1);
    log_ring[log_head % LOG_LINES][LOG_LINE_MAX - 1] = '\0';
    log_head++;
    if (log_count < LOG_LINES) log_count++;
    pthread_mutex_unlock(&log_ring_mutex);
}

/* ================================================================
 * Public: tui_prompt
 * ================================================================ */

int tui_prompt(const char *label, char *out, int maxlen) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int pw = (int)strlen(label) + maxlen + 6;
    if (pw > cols - 4) pw = cols - 4;
    int ph = 3, py = (rows - ph) / 2, px = (cols - pw) / 2;

    WINDOW *pop = newwin(ph, pw, py, px);
    wbkgd(pop, COLOR_PAIR(CP_HILIGHT));
    box(pop, 0, 0);
    mvwprintw(pop, 1, 2, "%s: ", label);
    wrefresh(pop);
    echo(); curs_set(1); nodelay(pop, FALSE);

    char buf[256] = {0};
    int rc = wgetnstr(pop, buf,
                      maxlen < (int)sizeof(buf) - 1 ? maxlen : (int)sizeof(buf) - 1);

    noecho(); curs_set(0); nodelay(stdscr, TRUE);
    delwin(pop);
    touchwin(stdscr);
    refresh();

    if (rc == ERR) return -1;
    strncpy(out, buf, maxlen - 1);
    out[maxlen - 1] = '\0';
    return 0;
}

/* ================================================================
 * Public: tui_init
 * ================================================================ */

void tui_init(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        init_pair(CP_HEADER,  COLOR_CYAN,   COLOR_BLACK);
        init_pair(CP_GOOD,    COLOR_GREEN,  COLOR_BLACK);
        init_pair(CP_WARN,    COLOR_YELLOW, COLOR_BLACK);
        init_pair(CP_ALERT,   COLOR_RED,    COLOR_BLACK);
        init_pair(CP_DIM,     COLOR_WHITE,  COLOR_BLACK);
        init_pair(CP_HILIGHT, COLOR_BLACK,  COLOR_CYAN);
    }

    memset(thread_last_sent, 0, sizeof(thread_last_sent));
    memset(thread_cur_pps,   0, sizeof(thread_cur_pps));
    memset(spark_buf,        0, sizeof(spark_buf));

    recreate_windows();
    last_tick = time(NULL);

    tui_log("Ready — iface: %s  mode: %s  threads: %d",
            conf.interface, mode_to_string(conf.mode), conf.threads);
    if (conf.session_duration > 0)
        tui_log("Session timer: %d seconds", conf.session_duration);
    tui_log("Press [s] or Enter to begin injecting");

    /* Show disclaimer and walkthrough on first launch */
    {
        char dir[PROFILE_DIR_MAX];
        char path[PROFILE_DIR_MAX + 28];
        profiles_dir(dir, sizeof(dir));

        snprintf(path, sizeof(path), "%s/.disclaimer_accepted", dir);
        if (access(path, F_OK) != 0)
            show_disclaimer = 1;

        snprintf(path, sizeof(path), "%s/.tui_intro_seen", dir);
        if (access(path, F_OK) != 0) {
            show_intro = 1;
            intro_page = 0;
        }
    }
}

/* ================================================================
 * Public: tui_cleanup
 * ================================================================ */

void tui_cleanup(void) {
    if (w_header) delwin(w_header);
    if (w_stats)  delwin(w_stats);
    if (w_config) delwin(w_config);
    if (w_nccl)   delwin(w_nccl);
    if (w_log)    delwin(w_log);
    if (w_keys)   delwin(w_keys);
    endwin();
}

/* ================================================================
 * Draw: authorization disclaimer (shown every launch)
 * ================================================================ */

static void draw_disclaimer(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int pw = 68;
    if (pw > cols - 2) pw = cols - 2;
    int ph = 22;
    if (ph > rows - 2) ph = rows - 2;
    int py = (rows - ph) / 2, px = (cols - pw) / 2;

    WINDOW *w = newwin(ph, pw, py, px);
    wbkgd(w, COLOR_PAIR(CP_DIM));
    box(w, 0, 0);

    wattron(w, A_BOLD | COLOR_PAIR(CP_ALERT));
    mvwprintw(w, 0, (pw - 24) / 2, " AUTHORIZED USE ONLY ");
    wattroff(w, A_BOLD | COLOR_PAIR(CP_ALERT));

    int r = 2;
    wattron(w, A_BOLD);
    mvwprintw(w, r++, 3, "Basidium is a hardware stress and fault-injection");
    mvwprintw(w, r++, 3, "tool intended exclusively for authorized testing.");
    wattroff(w, A_BOLD);

    r++;
    wattron(w, COLOR_PAIR(CP_WARN));
    mvwprintw(w, r++, 3, "You may only run this tool if ALL of the following");
    mvwprintw(w, r++, 3, "conditions are met:");
    wattroff(w, COLOR_PAIR(CP_WARN));

    r++;
    mvwprintw(w, r++, 5, "1. The target hardware is airgapped and isolated");
    mvwprintw(w, r++, 7, "from any production or shared network.");
    mvwprintw(w, r++, 5, "2. You own the equipment or have explicit written");
    mvwprintw(w, r++, 7, "authorization from the owner to conduct this test.");
    mvwprintw(w, r++, 5, "3. You are not targeting infrastructure, devices,");
    mvwprintw(w, r++, 7, "or networks belonging to any other party.");
    mvwprintw(w, r++, 5, "4. You accept full legal and ethical responsibility");
    mvwprintw(w, r++, 7, "for all traffic generated by this session.");

    r++;
    wattron(w, COLOR_PAIR(CP_ALERT) | A_BOLD);
    mvwprintw(w, r++, 3, "Unauthorized use may violate computer fraud and");
    mvwprintw(w, r++, 3, "abuse laws. Misuse is your sole responsibility.");
    wattroff(w, COLOR_PAIR(CP_ALERT) | A_BOLD);

    r++;
    wattron(w, COLOR_PAIR(CP_GOOD) | A_BOLD);
    mvwprintw(w, ph - 2, 3, "Press Y to accept and continue, any other key to exit.");
    wattroff(w, COLOR_PAIR(CP_GOOD) | A_BOLD);

    wrefresh(w);

    nodelay(stdscr, FALSE);
    int ch = getch();
    nodelay(stdscr, TRUE);

    delwin(w);
    touchwin(stdscr);
    refresh();

    if (ch == 'y' || ch == 'Y') {
        /* Mark accepted so it never shows again */
        char dir[PROFILE_DIR_MAX];
        char path[PROFILE_DIR_MAX + 28];
        profiles_dir(dir, sizeof(dir));
        snprintf(path, sizeof(path), "%s/.disclaimer_accepted", dir);
        FILE *f = fopen(path, "w");
        if (f) { fputs("1\n", f); fclose(f); }
        show_disclaimer = 0;
    } else {
        /* User declined — shut down cleanly */
        endwin();
        fprintf(stderr, "Aborted: authorization not confirmed.\n");
        exit(0);
    }
}

/* ================================================================
 * Draw: first-time intro walkthrough
 * ================================================================ */

static void intro_mark_seen(void) {
    char dir[PROFILE_DIR_MAX];
    char path[PROFILE_DIR_MAX + 24];
    profiles_dir(dir, sizeof(dir));
    snprintf(path, sizeof(path), "%s/.tui_intro_seen", dir);
    FILE *f = fopen(path, "w");
    if (f) { fputs("1\n", f); fclose(f); }
}

static void draw_intro(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int ph = 22, pw = 66;
    if (ph > rows - 2) ph = rows - 2;
    if (pw > cols - 2) pw = cols - 2;
    int py = (rows - ph) / 2, px = (cols - pw) / 2;

    WINDOW *w = newwin(ph, pw, py, px);
    wbkgd(w, COLOR_PAIR(CP_DIM));
    box(w, 0, 0);

    char pg[20];
    snprintf(pg, sizeof(pg), " %d / %d ", intro_page + 1, INTRO_PAGES);
    wattron(w, A_BOLD | COLOR_PAIR(CP_HEADER));
    mvwprintw(w, 0, (pw - (int)strlen(pg)) / 2, "%s", pg);
    wattroff(w, A_BOLD | COLOR_PAIR(CP_HEADER));

    int r = 2;

    switch (intro_page) {

    case 0:
        wattron(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        mvwprintw(w, r++, 2, "Welcome to Basidium");
        wattroff(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        r++;
        mvwprintw(w, r++, 2, "Basidium is a Layer-2 hardware stress and");
        mvwprintw(w, r++, 2, "evaluation tool for authorized lab testing.");
        r++;
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 2, "TUI LAYOUT");
        wattroff(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 4, "Top bar    Version, interface, mode, status");
        mvwprintw(w, r++, 4, "Left pane  Live PPS, packet total, sparkline");
        mvwprintw(w, r++, 4, "Right pane Active configuration summary");
        mvwprintw(w, r++, 4, "Log panel  Timestamped event stream");
        mvwprintw(w, r++, 4, "Keys bar   Available hotkeys for current state");
        break;

    case 1:
        wattron(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        mvwprintw(w, r++, 2, "Starting a Session");
        wattroff(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        r++;
        mvwprintw(w, r++, 2, "Basidium launches in STANDBY — no frames are");
        mvwprintw(w, r++, 2, "sent until you explicitly start the session.");
        r++;
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 2, "KEY          ACTION");
        wattroff(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 4, "s / Enter    Begin injecting frames");
        mvwprintw(w, r++, 4, "Space        Pause or resume mid-session");
        mvwprintw(w, r++, 4, "q            Quit (stops all worker threads)");
        r++;
        mvwprintw(w, r++, 2, "The status badge (top-right) shows:");
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 4, "STANDBY");
        wattroff(w, COLOR_PAIR(CP_WARN));
        wattron(w, COLOR_PAIR(CP_GOOD));
        mvwaddstr(w, r - 1, 13, "  RUNNING");
        wattroff(w, COLOR_PAIR(CP_GOOD));
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwaddstr(w, r - 1, 23, "  PAUSED");
        wattroff(w, COLOR_PAIR(CP_WARN));
        break;

    case 2:
        wattron(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        mvwprintw(w, r++, 2, "Live Tuning");
        wattroff(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        r++;
        mvwprintw(w, r++, 2, "Most settings can be changed while the");
        mvwprintw(w, r++, 2, "session is running — no restart needed.");
        r++;
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 2, "KEY          ACTION");
        wattroff(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 4, "+ / =        Rate +1000 pps");
        mvwprintw(w, r++, 4, "-            Rate -1000 pps  (0 = unlimited)");
        mvwprintw(w, r++, 4, "o            Set source OUI  (blank = random)");
        mvwprintw(w, r++, 4, "v            Set VLAN ID     (0 = untagged)");
        mvwprintw(w, r++, 4, "l            Load a .pcap file for replay");
        r++;
        mvwprintw(w, r++, 2, "All changes take effect on the next frame burst.");
        break;

    case 3:
        wattron(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        mvwprintw(w, r++, 2, "Profiles & Advanced Features");
        wattroff(w, A_BOLD | COLOR_PAIR(CP_GOOD));
        r++;
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 2, "PROFILES  [p]");
        wattroff(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 4, "Save the current config as a named profile");
        mvwprintw(w, r++, 4, "and reload it in any future session.");
        mvwprintw(w, r++, 4, "Profiles are stored in ~/.basidium/");
        r++;
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 2, "ADVANCED FLAGS (pass at launch)");
        wattroff(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, r++, 4, "--sweep start:end:step[:hold_s]");
        mvwprintw(w, r++, 6, "Automated PPS ramp — pair with --report");
        mvwprintw(w, r++, 4, "--detect    Fail-open detection & alerting");
        r++;
        mvwprintw(w, r++, 2, "Press ? at any time for the full key reference.");
        break;
    }

    wattron(w, COLOR_PAIR(CP_DIM) | A_DIM);
    if (intro_page < INTRO_PAGES - 1)
        mvwprintw(w, ph - 2, 2,
                  "[Right/Tab] next   [Left] back   [Enter/Esc] skip tour");
    else
        mvwprintw(w, ph - 2, 2,
                  "[Left] back   [Enter/Esc] get started");
    wattroff(w, A_DIM);

    wrefresh(w);

    nodelay(stdscr, FALSE);
    int ch = getch();
    nodelay(stdscr, TRUE);

    delwin(w);
    touchwin(stdscr);
    refresh();

    if (ch == KEY_RIGHT || ch == '\t') {
        if (intro_page < INTRO_PAGES - 1) {
            intro_page++;
        } else {
            intro_mark_seen();
            show_intro = 0;
        }
    } else if (ch == KEY_LEFT) {
        if (intro_page > 0) intro_page--;
    } else if (ch == '\n' || ch == KEY_ENTER || ch == 27) {
        intro_mark_seen();
        show_intro = 0;
    }
}

/* ================================================================
 * Draw: help overlay
 * ================================================================ */

/* Help content entry: text + flag indicating a section header */
typedef struct { char text[80]; int is_header; } help_entry_t;

#define HELP_MAX 120

static void draw_help(void) {
    /* Build the full reference content once per open */
    static help_entry_t lines[HELP_MAX];
    int n = 0;

#define HL(t)  do { strncpy(lines[n].text,(t),79); lines[n].is_header=0; n++; } while(0)
#define HH(t)  do { strncpy(lines[n].text,(t),79); lines[n].is_header=1; n++; } while(0)
#define HBLK() do { lines[n].text[0]='\0';          lines[n].is_header=0; n++; } while(0)

    HH("TUI HOTKEYS");
    HBLK();
    HH("SESSION CONTROL");
    HL("  s / Enter    Start injecting");
    HL("  Space        Pause / resume");
    HL("  q            Quit");
    HBLK();
    HH("LIVE TUNING");
    HL("  + / =        Rate +1000 pps");
    HL("  -            Rate -1000 pps  (0 = unlimited)");
    HL("  o            Set source OUI  (blank = random)");
    HL("  v            Set VLAN ID     (0 = untagged)");
    HL("  l            Load .pcap file for replay");
    HBLK();
    HH("PROFILES");
    HL("  p            Open profile menu");
    HL("  (in menu)    Up/Down select, Enter load, S save, Esc close");
    if (conf.nccl) {
        HBLK();
        HH("NCCL");
        HL("  n            Launch NCCL test");
        HL("  b            Set NCCL baseline from last result");
    }
    HBLK();
    HH("---------- CLI OPTIONS ----------");
    HBLK();
    HH("FLOOD MODES  (-M flag)");
    HL("  mac    Standard MAC flood — fills CAM tables (default)");
    HL("  arp    Gratuitous ARP broadcast flood");
    HL("  dhcp   DHCP Discover starvation flood");
    HL("  pfc    802.1Qbb PFC PAUSE flood (RoCE/RDMA fabric testing)");
    HL("  nd     IPv6 Neighbor Discovery flood (ICMPv6 NS)");
    HL("  lldp   LLDP frame flood (stresses switch CPU / LLDP table)");
    HL("  stp    STP TCN BPDU flood (forces periodic MAC table flush)");
    HL("  igmp   IGMPv2 Membership Report flood");
    HBLK();
    HH("VLAN & PFC");
    HL("  -V <id>              802.1Q VLAN tag (1-4094)");
    HL("  --vlan-pcp <0-7>     802.1p priority bits (default: 0)");
    HL("  --vlan-range <end>   Cycle VLAN IDs from -V to end");
    HL("  --qinq <outer-vid>   802.1ad QinQ outer tag");
    HL("  --pfc-priority <0-7> Priority class to pause (default: 3)");
    HL("  --pfc-quanta <val>   Pause quanta 0-65535 (default: 65535)");
    HBLK();
    HH("INTERFACE & PERFORMANCE");
    HL("  -i <iface>   Network interface (required)");
    HL("  -t <num>     Worker threads (default: 1, max: 16)");
    HL("  -r <pps>     Rate limit in pps (0 = unlimited)");
    HL("  -J <bytes>   Frame size 60-9216 bytes");
    HL("  -n <count>   Stop after N packets");
    HBLK();
    HH("STEALTH & TARGETING");
    HL("  -S <oui>     Stealth OUI prefix (e.g. 00:11:22)");
    HL("  -T <cidr>    Target IP subnet (e.g. 10.0.0.0/24)");
    HL("  -L           Learning mode — sniff real MACs, skip them");
    HL("  -A           Adaptive mode — throttle on fail-open");
    HL("  -U           Allow multicast source MACs");
    HL("  -R           Randomize DHCP client MAC independently");
    HBLK();
    HH("OUTPUT & LOGGING");
    HL("  -v              Verbose per-thread startup and live PPS");
    HL("  -l <file>       JSON event log file");
    HL("  --report [file] Write JSON session report on exit");
    HL("                  Default: basidium_report_<timestamp>.json");
    HBLK();
    HH("RATE SWEEP");
    HL("  --sweep start:end:step[:hold_s]");
    HL("          Ramp rate from start to end pps in steps");
    HL("          hold_s = seconds per step (default: 10)");
    HL("  Tip: pair --sweep with --report for benchmark JSON");
    HBLK();
    HH("NETWORK I/O");
    HL("  --pcap-out <file>     Write packets to .pcap");
    HL("  --pcap-replay <file>  Replay .pcap frames onto interface");
    HBLK();
    HH("PROFILES & SESSIONS");
    HL("  --profile <name>   Load named profile from ~/.basidium/");
    HL("  --duration <time>  Auto-stop (e.g. 30, 5m, 2h)");
    HBLK();
    HH("BURST & ADVANCED");
    HL("  --burst count:gap_ms   Send burst then pause gap_ms ms");
    HL("  --detect               Fail-open detection and alerting");
    HL("  --payload pattern      zeros ff dead incr (default: zeros)");
    HBLK();
    HH("DIAGNOSTICS");
    HL("  --selftest   Run built-in packet builder validation suite");

#undef HL
#undef HH
#undef HBLK

    /* Layout */
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    int ph = rows - 2;
    int pw = cols > 74 ? 74 : cols - 2;
    if (ph < 6) ph = 6;
    int py = (rows - ph) / 2, px = (cols - pw) / 2;
    int content_rows = ph - 3; /* rows between title and footer */

    WINDOW *w = newwin(ph, pw, py, px);
    wbkgd(w, COLOR_PAIR(CP_DIM));

    int scroll = 0;
    int done   = 0;
    int ch     = 0;

    nodelay(stdscr, FALSE);

    while (!done) {
        int max_scroll = n - content_rows;
        if (max_scroll < 0) max_scroll = 0;
        if (scroll > max_scroll) scroll = max_scroll;
        if (scroll < 0)          scroll = 0;

        werase(w);
        box(w, 0, 0);

        wattron(w, A_BOLD | COLOR_PAIR(CP_HEADER));
        mvwprintw(w, 0, (pw - 16) / 2, " Basidium  Help ");
        wattroff(w, A_BOLD | COLOR_PAIR(CP_HEADER));

        for (int i = 0; i < content_rows; i++) {
            int idx = scroll + i;
            if (idx >= n) break;
            if (lines[idx].is_header) {
                wattron(w, COLOR_PAIR(CP_WARN) | A_BOLD);
                mvwprintw(w, 1 + i, 2, "%-*.*s", pw - 4, pw - 4, lines[idx].text);
                wattroff(w, COLOR_PAIR(CP_WARN) | A_BOLD);
            } else {
                mvwprintw(w, 1 + i, 2, "%-*.*s", pw - 4, pw - 4, lines[idx].text);
            }
        }

        /* Scrollbar on right edge */
        if (n > content_rows) {
            int bar_h = (content_rows * content_rows) / n;
            if (bar_h < 1) bar_h = 1;
            int max_s = n - content_rows;
            int bar_y = (max_s > 0) ? (scroll * (content_rows - bar_h)) / max_s : 0;
            for (int i = 0; i < content_rows; i++)
                mvwaddch(w, 1 + i, pw - 2,
                         (i >= bar_y && i < bar_y + bar_h) ? ACS_BLOCK : ACS_VLINE);

            int pct = (int)((scroll + content_rows) * 100 / n);
            if (pct > 100) pct = 100;
            wattron(w, COLOR_PAIR(CP_DIM) | A_DIM);
            mvwprintw(w, ph - 2, 2,
                      "[Up/Dn/PgUp/PgDn/Home/End] scroll  [?/Esc] close  %d%%", pct);
            wattroff(w, A_DIM);
        } else {
            wattron(w, COLOR_PAIR(CP_DIM) | A_DIM);
            mvwprintw(w, ph - 2, 2, "[? / Esc / q] close");
            wattroff(w, A_DIM);
        }

        wrefresh(w);
        ch = getch();

        switch (ch) {
        case KEY_UP:    scroll--;                       break;
        case KEY_DOWN:  scroll++;                       break;
        case KEY_PPAGE: scroll -= content_rows - 1;    break;
        case KEY_NPAGE: scroll += content_rows - 1;    break;
        case KEY_HOME:  scroll = 0;                    break;
        case KEY_END:   scroll = n - content_rows;     break;
        case '?': case 27: case 'q': case 'Q': done = 1; break;
        }
    }

    nodelay(stdscr, TRUE);
    delwin(w);
    touchwin(stdscr);
    refresh();

    if (ch == 'q' || ch == 'Q') atomic_store(&is_running, 0);
    show_help = 0;
}

/* ================================================================
 * Draw: profile menu overlay
 * ================================================================ */

static void draw_profile_menu(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int ph = profile_count + 7;
    if (ph < 9)   ph = 9;
    if (ph > rows - 2) ph = rows - 2;
    int pw = 44;
    if (pw > cols - 2) pw = cols - 2;
    int py = (rows - ph) / 2, px = (cols - pw) / 2;

    WINDOW *w = newwin(ph, pw, py, px);
    wbkgd(w, COLOR_PAIR(CP_DIM));
    box(w, 0, 0);

    wattron(w, A_BOLD | COLOR_PAIR(CP_HEADER));
    mvwprintw(w, 0, (pw - 12) / 2, " profiles ");
    wattroff(w, A_BOLD | COLOR_PAIR(CP_HEADER));

    int usable = ph - 5;

    if (profile_count == 0) {
        mvwprintw(w, 2, 2, "(no saved profiles)");
    } else {
        int start = 0;
        if (profile_cursor >= usable) start = profile_cursor - usable + 1;
        for (int i = 0; i < usable && (start + i) < profile_count; i++) {
            int idx = start + i;
            if (idx == profile_cursor) {
                wattron(w, COLOR_PAIR(CP_HILIGHT) | A_BOLD);
                mvwprintw(w, 2 + i, 2, " %-*s ", pw - 6, profile_names[idx]);
                wattroff(w, COLOR_PAIR(CP_HILIGHT) | A_BOLD);
            } else {
                mvwprintw(w, 2 + i, 2, " %-*s ", pw - 6, profile_names[idx]);
            }
        }
    }

    wattron(w, COLOR_PAIR(CP_WARN));
    mvwprintw(w, ph - 3, 2, "Enter=load  s=save current  Esc=close");
    wattroff(w, COLOR_PAIR(CP_WARN));
    wrefresh(w);

    /* handle input for this overlay */
    nodelay(stdscr, FALSE);
    int ch;
    char save_name[PROFILE_NAME_MAX];

    while ((ch = getch()) != 27) { /* Esc closes */
        if (ch == KEY_UP && profile_cursor > 0) {
            profile_cursor--;
        } else if (ch == KEY_DOWN && profile_cursor < profile_count - 1) {
            profile_cursor++;
        } else if ((ch == '\n' || ch == KEY_ENTER) && profile_count > 0) {
            profiles_load(profile_names[profile_cursor], &conf);
            tui_log("Profile loaded: %s", profile_names[profile_cursor]);
            break;
        } else if (ch == 's' || ch == 'S') {
            /* save current config */
            delwin(w);
            touchwin(stdscr);
            refresh();
            nodelay(stdscr, TRUE);
            if (tui_prompt("Profile name", save_name, sizeof(save_name)) == 0
                    && strlen(save_name) > 0) {
                if (profiles_save(save_name, &conf) == 0) {
                    tui_log("Profile saved: %s", save_name);
                    /* refresh list */
                    profile_count = profiles_list(profile_names);
                } else {
                    tui_log("Failed to save profile: %s", save_name);
                }
            }
            show_profiles = 0;
            return;
        }
        /* redraw */
        werase(w);
        box(w, 0, 0);
        wattron(w, A_BOLD | COLOR_PAIR(CP_HEADER));
        mvwprintw(w, 0, (pw - 12) / 2, " profiles ");
        wattroff(w, A_BOLD | COLOR_PAIR(CP_HEADER));
        if (profile_count == 0) {
            mvwprintw(w, 2, 2, "(no saved profiles)");
        } else {
            int start = 0;
            if (profile_cursor >= usable) start = profile_cursor - usable + 1;
            for (int i = 0; i < usable && (start + i) < profile_count; i++) {
                int idx = start + i;
                if (idx == profile_cursor) {
                    wattron(w, COLOR_PAIR(CP_HILIGHT) | A_BOLD);
                    mvwprintw(w, 2 + i, 2, " %-*s ", pw - 6, profile_names[idx]);
                    wattroff(w, COLOR_PAIR(CP_HILIGHT) | A_BOLD);
                } else {
                    mvwprintw(w, 2 + i, 2, " %-*s ", pw - 6, profile_names[idx]);
                }
            }
        }
        wattron(w, COLOR_PAIR(CP_WARN));
        mvwprintw(w, ph - 3, 2, "Enter=load  s=save current  Esc=close");
        wattroff(w, COLOR_PAIR(CP_WARN));
        wrefresh(w);
    }

    nodelay(stdscr, TRUE);
    delwin(w);
    touchwin(stdscr);
    refresh();
    show_profiles = 0;
}

/* ================================================================
 * Public: tui_draw
 * ================================================================ */

void tui_draw(void) {
    /* Handle overlays first — they block until dismissed */
    if (show_disclaimer) { draw_disclaimer();  return; }
    if (show_intro)      { draw_intro();       return; }
    if (show_help)       { draw_help();        return; }
    if (show_profiles)   { draw_profile_menu(); return; }

    update_per_second();

    time_t now = time(NULL);

    /* ---- Header ---- */
    werase(w_header);
    box(w_header, 0, 0);
    wattron(w_header, COLOR_PAIR(CP_HEADER) | A_BOLD);

    mvwprintw(w_header, 1, 2,  "Basidium v%s", BASIDIUM_VERSION);
    mvwprintw(w_header, 1, 18, "iface: %-10s", conf.interface ? conf.interface : "?");
    mvwprintw(w_header, 1, 36, "mode: %-16s", mode_to_string(conf.mode));

    const char *status_str;
    int status_cp;
    if (!is_started)    { status_str = "STANDBY"; status_cp = CP_WARN;  }
    else if (is_paused) { status_str = "PAUSED";  status_cp = CP_WARN;  }
    else                { status_str = "RUNNING"; status_cp = CP_GOOD;  }

    wattron(w_header, COLOR_PAIR(status_cp));
    mvwprintw(w_header, 1, tui_cols - 12, "[%s]", status_str);
    wattroff(w_header, COLOR_PAIR(status_cp) | A_BOLD);

    /* Fail-open detection alert: blink red when switch has been detected in hub mode */
    if (fail_open_detected) {
        wattron(w_header, COLOR_PAIR(CP_ALERT) | A_BOLD | A_BLINK);
        mvwprintw(w_header, 1, tui_cols - 28, "[!FAIL-OPEN DETECTED!]");
        wattroff(w_header, COLOR_PAIR(CP_ALERT) | A_BOLD | A_BLINK);
    }

    wnoutrefresh(w_header);

    /* ---- Stats panel (left) ---- */
    werase(w_stats);
    box(w_stats, 0, 0);
    wattron(w_stats, A_BOLD);
    mvwprintw(w_stats, 0, 2, " LIVE STATS ");
    wattroff(w_stats, A_BOLD);

    int stats_w = tui_cols / 2;
    unsigned long long total = (unsigned long long)total_sent;
    time_t elapsed   = is_started ? (now - start_time) : 0;
    int hh = elapsed / 3600, mm = (elapsed % 3600) / 60, ss = elapsed % 60;

    wattron(w_stats, COLOR_PAIR(CP_GOOD) | A_BOLD);
    mvwprintw(w_stats, 1, 2, "PPS:    %12llu", cur_pps);
    wattroff(w_stats, COLOR_PAIR(CP_GOOD) | A_BOLD);
    mvwprintw(w_stats, 2, 2, "Total:  %12llu", total);
    mvwprintw(w_stats, 3, 2, "Uptime: %9d:%02d:%02d", hh, mm, ss);

    /* Session timer countdown */
    if (conf.session_duration > 0 && is_started) {
        int remaining = conf.session_duration - (int)elapsed;
        if (remaining < 0) remaining = 0;
        int tc = remaining < 30 ? CP_ALERT : remaining < 120 ? CP_WARN : CP_DIM;
        wattron(w_stats, COLOR_PAIR(tc));
        mvwprintw(w_stats, 4, 2, "Timer:  %9d:%02d:%02d",
                  remaining / 3600, (remaining % 3600) / 60, remaining % 60);
        wattroff(w_stats, COLOR_PAIR(tc));
    } else if (conf.adaptive) {
        mvwprintw(w_stats, 4, 2, "Bcast RX: %10llu", (unsigned long long)bcast_rx);
    }

    /* Sparkline */
    draw_sparkline(w_stats, 5, 2, stats_w - 4);

    /* Per-thread breakdown: two per row, capped at 4 threads shown */
    int trow = 6;
    int shown = conf.threads < 4 ? conf.threads : 4;
    for (int i = 0; i < shown; i += 2) {
        char buf[64] = {0};
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "T%d:%5.1fk", i,
                 thread_cur_pps[i] / 1000.0);
        strncat(buf, tmp, sizeof(buf) - 1);
        if (i + 1 < shown) {
            snprintf(tmp, sizeof(tmp), "  T%d:%5.1fk", i + 1,
                     thread_cur_pps[i + 1] / 1000.0);
            strncat(buf, tmp, sizeof(buf) - strlen(buf) - 1);
        }
        mvwprintw(w_stats, trow++, 2, "%s", buf);
    }
    if (conf.threads > 4)
        mvwprintw(w_stats, trow, 2, "+%d more threads", conf.threads - 4);

    /* NIC stats — always at the bottom row of the panel */
    if (nic_available) {
        uint64_t tx_bps = nic_cur.tx_bytes - nic_prev.tx_bytes;
        int      drop_color = (nic_cur.tx_dropped > 0 || nic_cur.tx_errors > 0)
                              ? CP_ALERT : CP_DIM;
        wattron(w_stats, COLOR_PAIR(drop_color));
        mvwprintw(w_stats, STATS_H - 2, 2,
                  "NIC %5.1fMB/s drp:%-4llu err:%-4llu",
                  tx_bps / 1048576.0,
                  (unsigned long long)(nic_cur.tx_dropped),
                  (unsigned long long)(nic_cur.tx_errors));
        wattroff(w_stats, COLOR_PAIR(drop_color));
    } else {
        wattron(w_stats, COLOR_PAIR(CP_WARN) | A_DIM);
        mvwprintw(w_stats, STATS_H - 2, 2, "NIC stats: n/a");
        wattroff(w_stats, COLOR_PAIR(CP_WARN) | A_DIM);
    }

    wnoutrefresh(w_stats);

    /* ---- Config panel (right) ---- */
    werase(w_config);
    box(w_config, 0, 0);
    wattron(w_config, A_BOLD);
    mvwprintw(w_config, 0, 2, " CONFIGURATION ");
    wattroff(w_config, A_BOLD);

    mvwprintw(w_config, 1, 2, "Mode:    %s", mode_to_string(conf.mode));

    /* Rate / sweep display */
    if (conf.sweep_enabled && (int)sweep_total_steps > 0) {
        int sn   = (int)sweep_step_num;
        int st   = (int)sweep_total_steps;
        int rem  = (int)sweep_hold_rem;
        wattron(w_config, COLOR_PAIR(CP_WARN));
        mvwprintw(w_config, 2, 2, "SWEEP  %d→%d  stp %d",
                  conf.sweep_start, conf.sweep_end, conf.sweep_step);
        mvwprintw(w_config, 3, 2, "Step %d/%d  next: %ds",
                  sn, st, rem);
        wattroff(w_config, COLOR_PAIR(CP_WARN));
    } else if (conf.pps > 0) {
        mvwprintw(w_config, 2, 2, "Rate:    %d pps", conf.pps);
    } else {
        mvwprintw(w_config, 2, 2, "Rate:    unlimited");
    }
    mvwprintw(w_config, 3, 2, "Threads: %d", conf.threads);
    if (conf.stealth)
        mvwprintw(w_config, 4, 2, "OUI:     %02x:%02x:%02x",
                  conf.stealth_oui[0], conf.stealth_oui[1], conf.stealth_oui[2]);
    else
        mvwprintw(w_config, 4, 2, "OUI:     random");
    mvwprintw(w_config, 5, 2, "PktSize: %d bytes",
              conf.packet_size ? conf.packet_size : 64);
    mvwprintw(w_config, 6, 2, "Learn: %-3s  Adapt: %-3s",
              conf.learning ? "on" : "off",
              conf.adaptive ? "on" : "off");
    if (conf.session_duration > 0)
        mvwprintw(w_config, 7, 2, "Duration: %ds", conf.session_duration);

    /* VLAN and PFC status on the last row */
    if (conf.vlan_id > 0 && conf.mode == MODE_PFC)
        mvwprintw(w_config, 8, 2, "VLAN: n/a (PFC)  PFC pri:%d q:0x%04x",
                  conf.pfc_priority, conf.pfc_quanta);
    else if (conf.vlan_id > 0)
        mvwprintw(w_config, 8, 2, "VLAN: %d  pcp:%d",
                  conf.vlan_id, conf.vlan_pcp);
    else if (conf.mode == MODE_PFC)
        mvwprintw(w_config, 8, 2, "PFC pri:%d  quanta:0x%04x",
                  conf.pfc_priority, conf.pfc_quanta);

    wnoutrefresh(w_config);

    /* ---- NCCL panel (optional) ---- */
    if (conf.nccl && w_nccl) {
        werase(w_nccl);
        box(w_nccl, 0, 0);
        wattron(w_nccl, A_BOLD);
        mvwprintw(w_nccl, 0, 2, " NCCL CORRELATION ");
        wattroff(w_nccl, A_BOLD);

        char summary[256];
        nccl_get_summary(summary, sizeof(summary));

        int ncp = CP_DIM;
        if (strstr(summary, "delta:")) {
            double d = 0.0;
            sscanf(strstr(summary, "delta:") + 6, "%lf", &d);
            ncp = (d < -10.0) ? CP_ALERT : (d < -3.0) ? CP_WARN : CP_GOOD;
        }
        wattron(w_nccl, COLOR_PAIR(ncp));
        mvwprintw(w_nccl, 1, 2, "%.*s", tui_cols - 4, summary);
        wattroff(w_nccl, COLOR_PAIR(ncp));
        mvwprintw(w_nccl, 2, 2, "binary: %s", nccl.binary);
        wnoutrefresh(w_nccl);
    }

    /* ---- Log panel ---- */
    werase(w_log);
    box(w_log, 0, 0);
    wattron(w_log, A_BOLD);
    mvwprintw(w_log, 0, 2, " EVENT LOG ");
    wattroff(w_log, A_BOLD);

    int log_rows, log_cols;
    getmaxyx(w_log, log_rows, log_cols);
    int displayable = log_rows - 2;

    pthread_mutex_lock(&log_ring_mutex);
    int start_idx = (log_count > displayable) ? log_count - displayable : 0;
    for (int i = 0; i < displayable && (start_idx + i) < log_count; i++) {
        int ridx = (log_head - log_count + start_idx + i + LOG_LINES * 4) % LOG_LINES;
        mvwprintw(w_log, i + 1, 2, "%.*s", log_cols - 4, log_ring[ridx]);
    }
    pthread_mutex_unlock(&log_ring_mutex);
    wnoutrefresh(w_log);

    /* ---- Keys bar ---- */
    werase(w_keys);
    wattron(w_keys, COLOR_PAIR(CP_HILIGHT));
    if (!is_started) {
        mvwprintw(w_keys, 0, 1,
            "[s/Enter]start  [o]ui  [+/-]rate  [p]rofiles  [?]help  [q]uit");
    } else {
        if (conf.nccl)
            mvwprintw(w_keys, 0, 1,
                "[sp]pause  [+/-]rate  [o]ui  [p]rofiles  [n]ccl  [b]aseline  [l]oad-pcap  [?]help  [q]uit");
        else
            mvwprintw(w_keys, 0, 1,
                "[sp]pause  [+/-]rate  [o]ui  [p]rofiles  [l]oad-pcap  [?]help  [q]uit");
    }
    wattroff(w_keys, COLOR_PAIR(CP_HILIGHT));
    wnoutrefresh(w_keys);

    doupdate();
}

/* ================================================================
 * Public: tui_input
 * ================================================================ */

int tui_input(int ch) {
    char buf[256];

    switch (ch) {
    case 'q': case 'Q':
        return 1;

    case '?':
        show_help = 1;
        break;

    case 'p': case 'P':
        profile_count  = profiles_list(profile_names);
        profile_cursor = 0;
        show_profiles  = 1;
        break;

    case 's': case 'S': case '\n': case KEY_ENTER:
        if (!is_started) {
            start_time = time(NULL);  /* begin duration timer from actual start */
            atomic_store(&is_started, 1);
            tui_log("Started — injecting on %s", conf.interface);
        }
        break;

    case ' ':
        if (!is_started) break;
        if (is_paused) {
            atomic_store(&is_paused, 0);
            tui_log("Resumed");
        } else {
            atomic_store(&is_paused, 1);
            tui_log("Paused");
        }
        break;

    case '+': case '=':
        conf.pps = (conf.pps <= 0) ? 1000 : conf.pps + 1000;
        tui_log("Rate: %d pps", conf.pps);
        break;

    case '-':
        conf.pps -= 1000;
        if (conf.pps < 0) conf.pps = 0;
        tui_log("Rate: %s", conf.pps ? "" : "unlimited");
        if (conf.pps) tui_log("%d pps", conf.pps);
        break;

    case 'o': case 'O':
        if (tui_prompt("OUI (xx:xx:xx, blank=random)", buf, sizeof(buf)) == 0) {
            if (strlen(buf) == 0) {
                conf.stealth = 0;
                tui_log("OUI: random");
            } else {
                unsigned int a, b, c;
                if (sscanf(buf, "%x:%x:%x", &a, &b, &c) == 3) {
                    conf.stealth_oui[0] = (uint8_t)(a & 0xFF);
                    conf.stealth_oui[1] = (uint8_t)(b & 0xFF);
                    conf.stealth_oui[2] = (uint8_t)(c & 0xFF);
                    conf.stealth = 1;
                    tui_log("OUI: %02x:%02x:%02x", a, b, c);
                } else {
                    tui_log("Invalid OUI — expected xx:xx:xx");
                }
            }
        }
        break;

    case 'n': case 'N':
        if (!conf.nccl) { tui_log("NCCL not enabled — relaunch with --nccl"); break; }
        if (nccl_launch() == 0)
            tui_log("NCCL test launched: %s", nccl.binary);
        else
            tui_log("NCCL: already running or launch failed");
        break;

    case 'b': case 'B':
        if (!conf.nccl) break;
        nccl_set_baseline();
        tui_log("NCCL baseline: %.1f GB/s busbw", nccl.baseline_bus_bw);
        break;

    case 'v': case 'V':
        if (tui_prompt("VLAN ID (0=untagged, 1-4094)", buf, sizeof(buf)) == 0
                && strlen(buf) > 0) {
            int vid = atoi(buf);
            if (vid < 0 || vid > 4094) {
                tui_log("Invalid VLAN ID %d", vid);
            } else {
                conf.vlan_id = vid;
                tui_log("VLAN: %s", vid ? "" : "untagged");
                if (vid) tui_log("%d", vid);
            }
        }
        break;

    case 'l': case 'L':
        if (tui_prompt("PCAP file to replay", buf, sizeof(buf)) == 0
                && strlen(buf) > 0) {
            free(conf.pcap_replay_file);
            conf.pcap_replay_file = strdup(buf);
            tui_log("PCAP queued: %s (restart to apply)", buf);
        }
        break;

    case KEY_RESIZE:
        recreate_windows();
        clear();
        refresh();
        break;
    }

    return 0;
}

#endif /* HAVE_TUI */
