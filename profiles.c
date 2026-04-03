/*
 * profiles.c — named config profile save/load
 */
#include "profiles.h"

#include <dirent.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void profiles_dir(char *out, size_t len) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    snprintf(out, len, "%s/.basidium", home);
}

static void ensure_dir(const char *path) {
    mkdir(path, 0755);
}

int profiles_save(const char *name, const struct config *conf) {
    char dir[PROFILE_DIR_MAX];
    profiles_dir(dir, sizeof(dir));
    ensure_dir(dir);

    char path[PROFILE_DIR_MAX + PROFILE_NAME_MAX + 8];
    snprintf(path, sizeof(path), "%s/%s.conf", dir, name);

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "# Basidium profile: %s\n", name);
    fprintf(fp, "interface=%s\n",        conf->interface ? conf->interface : "");
    fprintf(fp, "mode=%d\n",             conf->mode);
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
    char dir[PROFILE_DIR_MAX];
    profiles_dir(dir, sizeof(dir));

    char path[PROFILE_DIR_MAX + PROFILE_NAME_MAX + 8];
    snprintf(path, sizeof(path), "%s/%s.conf", dir, name);

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[64], val[256];
        if (sscanf(line, "%63[^=]=%255[^\n]", key, val) != 2) continue;

        if      (strcmp(key, "interface")         == 0) { free(conf->interface); conf->interface = strdup(val); }
        else if (strcmp(key, "mode")              == 0) conf->mode             = atoi(val);
        else if (strcmp(key, "threads")           == 0) conf->threads          = atoi(val);
        else if (strcmp(key, "pps")               == 0) conf->pps              = atoi(val);
        else if (strcmp(key, "packet_size")       == 0) conf->packet_size      = atoi(val);
        else if (strcmp(key, "stealth")           == 0) conf->stealth          = atoi(val);
        else if (strcmp(key, "stealth_oui")       == 0) {
            unsigned int a, b, c;
            if (sscanf(val, "%x:%x:%x", &a, &b, &c) == 3) {
                conf->stealth_oui[0] = a;
                conf->stealth_oui[1] = b;
                conf->stealth_oui[2] = c;
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
    return 0;
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
