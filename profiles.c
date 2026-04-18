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
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

void profiles_dir(char *out, size_t len) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    snprintf(out, len, "%s/.basidium", home);
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

int profiles_save(const char *name, const struct config *conf) {
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
    fprintf(fp, "interface=%s\n",        conf->interface ? conf->interface : "");
    fprintf(fp, "mode=%s\n",             mode_to_string(conf->mode));
    fprintf(fp, "threads=%d\n",          conf->threads);
    fprintf(fp, "pps=%d\n",              conf->pps);
    fprintf(fp, "packet_size=%d\n",      conf->packet_size);
    fprintf(fp, "stealth=%d\n",          conf->stealth);
    fprintf(fp, "stealth_oui=%02x:%02x:%02x\n",
            conf->stealth_oui[0], conf->stealth_oui[1], conf->stealth_oui[2]);
    fprintf(fp, "learning=%d\n",         conf->learning);
    fprintf(fp, "adaptive=%d\n",         conf->adaptive);
    fprintf(fp, "allow_multicast=%d\n",  conf->allow_multicast);
    fprintf(fp, "random_client_mac=%d\n",conf->random_client_mac);
    fprintf(fp, "session_duration=%d\n", conf->session_duration);
    fprintf(fp, "nccl=%d\n",             conf->nccl);
    fprintf(fp, "vlan_id=%d\n",          conf->vlan_id);
    fprintf(fp, "vlan_pcp=%d\n",         conf->vlan_pcp);
    fprintf(fp, "vlan_range_end=%d\n",   conf->vlan_range_end);
    fprintf(fp, "qinq_outer_vid=%d\n",   conf->qinq_outer_vid);
    fprintf(fp, "payload_pattern=%d\n",  conf->payload_pattern);
    fprintf(fp, "pfc_priority=%d\n",     conf->pfc_priority);
    fprintf(fp, "pfc_quanta=%d\n",       conf->pfc_quanta);
    fprintf(fp, "burst_count=%d\n",      conf->burst_count);
    fprintf(fp, "burst_gap_ms=%d\n",     conf->burst_gap_ms);
    fprintf(fp, "detect_failopen=%d\n",  conf->detect_failopen);
    fprintf(fp, "sweep_enabled=%d\n",    conf->sweep_enabled);
    fprintf(fp, "sweep_start=%d\n",      conf->sweep_start);
    fprintf(fp, "sweep_end=%d\n",        conf->sweep_end);
    fprintf(fp, "sweep_step=%d\n",       conf->sweep_step);
    fprintf(fp, "sweep_hold=%d\n",       conf->sweep_hold);

    fclose(fp);
    return 0;
}

int profiles_load(const char *name, struct config *conf) {
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
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[64], val[256];
        if (sscanf(line, "%63[^=]=%255[^\n]", key, val) != 2) continue;

        if      (strcmp(key, "interface")         == 0) { free(conf->interface); conf->interface = strdup(val); }
        else if (strcmp(key, "mode")              == 0) conf->mode             = mode_from_string(val);
        else if (strcmp(key, "threads")           == 0) conf->threads          = atoi(val);
        else if (strcmp(key, "pps")               == 0) conf->pps              = atoi(val);
        else if (strcmp(key, "packet_size")       == 0) conf->packet_size      = atoi(val);
        else if (strcmp(key, "stealth")           == 0) conf->stealth          = atoi(val);
        else if (strcmp(key, "stealth_oui")       == 0) {
            unsigned int a, b, c;
            if (sscanf(val, "%x:%x:%x", &a, &b, &c) == 3) {
                conf->stealth_oui[0] = (uint8_t)(a & 0xFF);
                conf->stealth_oui[1] = (uint8_t)(b & 0xFF);
                conf->stealth_oui[2] = (uint8_t)(c & 0xFF);
            }
        }
        else if (strcmp(key, "learning")          == 0) conf->learning         = atoi(val);
        else if (strcmp(key, "adaptive")          == 0) conf->adaptive         = atoi(val);
        else if (strcmp(key, "allow_multicast")   == 0) conf->allow_multicast  = atoi(val);
        else if (strcmp(key, "random_client_mac") == 0) conf->random_client_mac = atoi(val);
        else if (strcmp(key, "session_duration")  == 0) conf->session_duration = atoi(val);
        else if (strcmp(key, "nccl")              == 0) conf->nccl             = atoi(val);
        else if (strcmp(key, "vlan_id")           == 0) conf->vlan_id          = atoi(val);
        else if (strcmp(key, "vlan_pcp")          == 0) conf->vlan_pcp         = atoi(val);
        else if (strcmp(key, "vlan_range_end")    == 0) conf->vlan_range_end   = atoi(val);
        else if (strcmp(key, "qinq_outer_vid")    == 0) conf->qinq_outer_vid   = atoi(val);
        else if (strcmp(key, "payload_pattern")   == 0) conf->payload_pattern  = atoi(val);
        else if (strcmp(key, "pfc_priority")      == 0) conf->pfc_priority     = atoi(val);
        else if (strcmp(key, "pfc_quanta")        == 0) conf->pfc_quanta       = atoi(val);
        else if (strcmp(key, "burst_count")       == 0) conf->burst_count      = atoi(val);
        else if (strcmp(key, "burst_gap_ms")      == 0) conf->burst_gap_ms     = atoi(val);
        else if (strcmp(key, "detect_failopen")   == 0) conf->detect_failopen  = atoi(val);
        else if (strcmp(key, "sweep_enabled")     == 0) conf->sweep_enabled    = atoi(val);
        else if (strcmp(key, "sweep_start")       == 0) conf->sweep_start      = atoi(val);
        else if (strcmp(key, "sweep_end")         == 0) conf->sweep_end        = atoi(val);
        else if (strcmp(key, "sweep_step")        == 0) conf->sweep_step       = atoi(val);
        else if (strcmp(key, "sweep_hold")        == 0) conf->sweep_hold       = atoi(val);
    }

    fclose(fp);
    return profile_validate(conf, name);
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
