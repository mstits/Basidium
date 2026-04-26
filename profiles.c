/*
 * profiles.c — named config profile save/load
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 */
#define _GNU_SOURCE
#include "profiles.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Trim trailing CR/LF/whitespace.  Profile files edited on Windows or copied
 * through CRLF-translating tools end up with stray \r that mode_from_string
 * rejects ("mac\r" != "mac"), so loaders silently fall back to defaults.
 * Trimming up front makes the rest of the parser CRLF-agnostic.
 */
static void rstrip(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\r' || s[n-1] == '\n' ||
                     s[n-1] == ' '  || s[n-1] == '\t'))
        s[--n] = '\0';
}

/* Validated int from a profile value string.  Reports the field name on
 * failure rather than silently returning 0 the way atoi() does. */
static int parse_int_field(const char *val, const char *field,
                           int lo, int hi, const char *name) {
    char *end = NULL;
    errno = 0;
    long v = strtol(val, &end, 10);
    if (end == val || (end && *end != '\0') || errno == ERANGE) {
        fprintf(stderr, "profile '%s': %s='%s' is not an integer\n",
                name, field, val);
        return INT_MIN;
    }
    if (v < lo || v > hi) {
        fprintf(stderr, "profile '%s': %s=%ld out of range (%d..%d)\n",
                name, field, v, lo, hi);
        return INT_MIN;
    }
    return (int)v;
}

/*
 * Sanitize a profile name to prevent path traversal.
 * Rejects names containing '/', '..', or starting with '.'.
 * Returns 1 if safe, 0 if rejected.
 */
static int profile_name_safe(const char *name) {
    if (!name || name[0] == '\0') return 0;
    if (name[0] == '.') return 0;
    if (strstr(name, "..")) return 0;
    if (strchr(name, '/')) return 0;
    if (strchr(name, '\\')) return 0;
    /* only allow alphanumeric, dash, underscore */
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
            return 0;
    }
    return 1;
}

/*
 * Resolve the profile directory.  Order:
 *   1. $BASIDIUM_PROFILE_DIR (explicit override)
 *   2. $XDG_CONFIG_HOME/basidium  (XDG basedir spec)
 *   3. $HOME/.basidium            (legacy, kept for compat)
 *   4. /tmp/.basidium             (last-ditch when no HOME)
 * If the legacy ~/.basidium exists and the XDG path does not, we keep using
 * the legacy path so existing profiles continue to load without migration.
 */
void profiles_dir(char *out, size_t len) {
    const char *override_dir = getenv("BASIDIUM_PROFILE_DIR");
    if (override_dir && override_dir[0]) {
        snprintf(out, len, "%s", override_dir);
        return;
    }
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    char legacy[PROFILE_DIR_MAX];
    snprintf(legacy, sizeof(legacy), "%s/.basidium", home);
    struct stat st;
    if (stat(legacy, &st) == 0 && S_ISDIR(st.st_mode)) {
        snprintf(out, len, "%s", legacy);
        return;
    }
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0])
        snprintf(out, len, "%s/basidium", xdg);
    else
        snprintf(out, len, "%s", legacy);
}

static int ensure_dir(const char *path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "profiles: cannot create %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Validate a loaded profile's numeric fields. Any out-of-range value is
 * treated as profile corruption — emit a diagnostic and reject the load
 * rather than silently clamping, so the operator fixes the profile instead
 * of running with surprising values.
 */
static int profile_validate(const struct config *c, const char *name) {
    const char *err = NULL;
    if (c->threads < 0 || c->threads > MAX_THREADS)
        err = "threads out of range (0..16)";
    else if (c->pps < 0)
        err = "pps must be >= 0";
    else if (c->packet_size != 0 &&
             (c->packet_size < 60 || c->packet_size > MAX_PACKET_SIZE))
        err = "packet_size must be 0 or 60..9216";
    else if (c->vlan_id < 0 || c->vlan_id > 4094)
        err = "vlan_id must be 0..4094";
    else if (c->vlan_pcp < 0 || c->vlan_pcp > 7)
        err = "vlan_pcp must be 0..7";
    else if (c->vlan_range_end < 0 || c->vlan_range_end > 4094)
        err = "vlan_range_end must be 0..4094";
    else if (c->qinq_outer_vid < 0 || c->qinq_outer_vid > 4094)
        err = "qinq_outer_vid must be 0..4094";
    else if (c->pfc_priority < 0 || c->pfc_priority > 7)
        err = "pfc_priority must be 0..7";
    else if (c->pfc_quanta < 0 || c->pfc_quanta > 0xFFFF)
        err = "pfc_quanta must be 0..65535";
    else if (c->payload_pattern < 0 || c->payload_pattern > 3)
        err = "payload_pattern must be 0..3";
    else if (c->session_duration < 0)
        err = "session_duration must be >= 0";

    if (err) {
        fprintf(stderr, "profile '%s': %s\n", name, err);
        return -1;
    }
    return 0;
}

int profiles_save(const char *name, const struct config *cfg) {
    if (!profile_name_safe(name)) return -1;

    char dir[PROFILE_DIR_MAX];
    profiles_dir(dir, sizeof(dir));
    if (ensure_dir(dir) != 0) return -1;

    char path[PROFILE_DIR_MAX + PROFILE_NAME_MAX + 8];
    snprintf(path, sizeof(path), "%s/%s.conf", dir, name);

    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "profiles: cannot write %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(fp, "# Basidium profile: %s\n", name);
    fprintf(fp, "interface=%s\n",        cfg->interface ? cfg->interface : "");
    fprintf(fp, "mode=%s\n",             mode_to_string(cfg->mode));
    fprintf(fp, "threads=%d\n",          cfg->threads);
    fprintf(fp, "pps=%d\n",              cfg->pps);
    fprintf(fp, "packet_size=%d\n",      cfg->packet_size);
    fprintf(fp, "stealth=%d\n",          cfg->stealth);
    fprintf(fp, "stealth_oui=%02x:%02x:%02x\n",
            cfg->stealth_oui[0], cfg->stealth_oui[1], cfg->stealth_oui[2]);
    fprintf(fp, "learning=%d\n",         cfg->learning);
    fprintf(fp, "adaptive=%d\n",         cfg->adaptive);
    fprintf(fp, "allow_multicast=%d\n",  cfg->allow_multicast);
    fprintf(fp, "random_client_mac=%d\n",cfg->random_client_mac);
    fprintf(fp, "session_duration=%d\n", cfg->session_duration);
    fprintf(fp, "nccl=%d\n",             cfg->nccl);
    fprintf(fp, "vlan_id=%d\n",          cfg->vlan_id);
    fprintf(fp, "vlan_pcp=%d\n",         cfg->vlan_pcp);
    fprintf(fp, "vlan_range_end=%d\n",   cfg->vlan_range_end);
    fprintf(fp, "qinq_outer_vid=%d\n",   cfg->qinq_outer_vid);
    fprintf(fp, "payload_pattern=%d\n",  cfg->payload_pattern);
    fprintf(fp, "pfc_priority=%d\n",     cfg->pfc_priority);
    fprintf(fp, "pfc_quanta=%d\n",       cfg->pfc_quanta);
    fprintf(fp, "burst_count=%d\n",      cfg->burst_count);
    fprintf(fp, "burst_gap_ms=%d\n",     cfg->burst_gap_ms);
    fprintf(fp, "detect_failopen=%d\n",  cfg->detect_failopen);
    fprintf(fp, "sweep_enabled=%d\n",    cfg->sweep_enabled);
    fprintf(fp, "sweep_start=%d\n",      cfg->sweep_start);
    fprintf(fp, "sweep_end=%d\n",        cfg->sweep_end);
    fprintf(fp, "sweep_step=%d\n",       cfg->sweep_step);
    fprintf(fp, "sweep_hold=%d\n",       cfg->sweep_hold);

    fclose(fp);
    return 0;
}

int profiles_load(const char *name, struct config *cfg) {
    if (!profile_name_safe(name)) {
        fprintf(stderr, "profiles: unsafe profile name '%s'\n",
                name ? name : "(null)");
        return -1;
    }

    char dir[PROFILE_DIR_MAX];
    profiles_dir(dir, sizeof(dir));

    char path[PROFILE_DIR_MAX + PROFILE_NAME_MAX + 8];
    snprintf(path, sizeof(path), "%s/%s.conf", dir, name);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "profiles: cannot open %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    char line[512];
    int  parse_err = 0;
    while (fgets(line, sizeof(line), fp)) {
        rstrip(line);
        if (line[0] == '#' || line[0] == '\0') continue;

        char key[64], val[256];
        if (sscanf(line, "%63[^=]=%255[^\n]", key, val) != 2) continue;

        /* macro to set a field via parse_int_field, surfacing failure. */
        #define SETI(field, lo, hi) do {                       \
            int v = parse_int_field(val, #field, (lo), (hi), name); \
            if (v == INT_MIN) { parse_err = 1; }              \
            else cfg->field = v;                              \
        } while (0)

        if      (strcmp(key, "interface")         == 0) { free(cfg->interface); cfg->interface = strdup(val); }
        else if (strcmp(key, "mode")              == 0) {
            flood_mode_t m = mode_from_string(val);
            if (m == MODE_INVALID) {
                fprintf(stderr, "profile '%s': mode='%s' is not a known mode\n",
                        name, val);
                parse_err = 1;
            } else {
                cfg->mode = m;
            }
        }
        else if (strcmp(key, "threads")           == 0) SETI(threads, 1, MAX_THREADS);
        else if (strcmp(key, "pps")               == 0) SETI(pps, 0, INT_MAX);
        else if (strcmp(key, "packet_size")       == 0) {
            int v = parse_int_field(val, "packet_size", 0, MAX_PACKET_SIZE, name);
            if (v == INT_MIN) parse_err = 1;
            else if (v != 0 && v < 60) {
                fprintf(stderr, "profile '%s': packet_size=%d (must be 0 or 60..%d)\n",
                        name, v, MAX_PACKET_SIZE);
                parse_err = 1;
            } else cfg->packet_size = v;
        }
        else if (strcmp(key, "stealth")           == 0) SETI(stealth, 0, 1);
        else if (strcmp(key, "stealth_oui")       == 0) {
            unsigned int a, b, c;
            if (sscanf(val, "%x:%x:%x", &a, &b, &c) != 3 ||
                a > 0xFF || b > 0xFF || c > 0xFF) {
                fprintf(stderr, "profile '%s': stealth_oui='%s' must be xx:xx:xx hex\n",
                        name, val);
                parse_err = 1;
            } else {
                cfg->stealth_oui[0] = (uint8_t)a;
                cfg->stealth_oui[1] = (uint8_t)b;
                cfg->stealth_oui[2] = (uint8_t)c;
            }
        }
        else if (strcmp(key, "learning")          == 0) SETI(learning, 0, 1);
        else if (strcmp(key, "adaptive")          == 0) SETI(adaptive, 0, 1);
        else if (strcmp(key, "allow_multicast")   == 0) SETI(allow_multicast, 0, 1);
        else if (strcmp(key, "random_client_mac") == 0) SETI(random_client_mac, 0, 1);
        else if (strcmp(key, "session_duration")  == 0) SETI(session_duration, 0, INT_MAX);
        else if (strcmp(key, "nccl")              == 0) SETI(nccl, 0, 1);
        else if (strcmp(key, "vlan_id")           == 0) SETI(vlan_id, 0, 4094);
        else if (strcmp(key, "vlan_pcp")          == 0) SETI(vlan_pcp, 0, 7);
        else if (strcmp(key, "vlan_range_end")    == 0) SETI(vlan_range_end, 0, 4094);
        else if (strcmp(key, "qinq_outer_vid")    == 0) SETI(qinq_outer_vid, 0, 4094);
        else if (strcmp(key, "payload_pattern")   == 0) SETI(payload_pattern, 0, 3);
        else if (strcmp(key, "pfc_priority")      == 0) SETI(pfc_priority, 0, 7);
        else if (strcmp(key, "pfc_quanta")        == 0) SETI(pfc_quanta, 0, 0xFFFF);
        else if (strcmp(key, "burst_count")       == 0) SETI(burst_count, 0, INT_MAX);
        else if (strcmp(key, "burst_gap_ms")      == 0) SETI(burst_gap_ms, 0, INT_MAX);
        else if (strcmp(key, "detect_failopen")   == 0) SETI(detect_failopen, 0, 1);
        else if (strcmp(key, "sweep_enabled")     == 0) SETI(sweep_enabled, 0, 1);
        else if (strcmp(key, "sweep_start")       == 0) SETI(sweep_start, 0, INT_MAX);
        else if (strcmp(key, "sweep_end")         == 0) SETI(sweep_end, 0, INT_MAX);
        else if (strcmp(key, "sweep_step")        == 0) SETI(sweep_step, 0, INT_MAX);
        else if (strcmp(key, "sweep_hold")        == 0) SETI(sweep_hold, 0, INT_MAX);
        #undef SETI
    }

    fclose(fp);
    if (parse_err) return -1;
    return profile_validate(cfg, name);
}

int profiles_list(char names[PROFILE_LIST_MAX][PROFILE_NAME_MAX]) {
    char dir[PROFILE_DIR_MAX];
    profiles_dir(dir, sizeof(dir));

    DIR *dp = opendir(dir);
    if (!dp) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dp)) && count < PROFILE_LIST_MAX) {
        if (ent->d_name[0] == '.') continue;
        size_t len = strlen(ent->d_name);
        if (len > 5 && strcmp(ent->d_name + len - 5, ".conf") == 0) {
            strncpy(names[count], ent->d_name, PROFILE_NAME_MAX - 1);
            names[count][PROFILE_NAME_MAX - 1] = '\0';
            names[count][len - 5] = '\0'; /* strip .conf */
            count++;
        }
    }
    closedir(dp);
    return count;
}
