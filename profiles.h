/*
 * profiles.h — save/load named config profiles
 * Stored as key=value text files in ~/.basidium/<name>.conf
 */
#ifndef PROFILES_H
#define PROFILES_H

#include "flood.h"

#define PROFILE_DIR_MAX  256
#define PROFILE_NAME_MAX  64
#define PROFILE_LIST_MAX  32

void profiles_dir(char *out, size_t len);
int  profiles_save(const char *name, const struct config *conf);
int  profiles_load(const char *name, struct config *conf);
int  profiles_list(char names[PROFILE_LIST_MAX][PROFILE_NAME_MAX]);

#endif /* PROFILES_H */
