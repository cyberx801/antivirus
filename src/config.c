#include "../include/config.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_KEYS  64
#define MAX_FEEDS 16

static struct { char key[64]; char value[512]; } kv[MAX_KEYS];
static int kv_count = 0;

static char feeds[MAX_FEEDS][512];
static int feed_count = 0;

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

int config_load(const char *path) {
    kv_count = 0;
    feed_count = 0;

    FILE *f = fopen(path, "r");
    if (!f) return -1; /* no config -> defaults */

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;

        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';

        char *k = trim(s);
        char *v = trim(eq + 1);

        if (strcmp(k, "feed") == 0) {
            if (feed_count < MAX_FEEDS) {
                strncpy(feeds[feed_count], v, sizeof(feeds[0]) - 1);
                feeds[feed_count][sizeof(feeds[0]) - 1] = '\0';
                feed_count++;
            }
        } else if (kv_count < MAX_KEYS) {
            strncpy(kv[kv_count].key, k, sizeof(kv[0].key) - 1);
            kv[kv_count].key[sizeof(kv[0].key) - 1] = '\0';
            strncpy(kv[kv_count].value, v, sizeof(kv[0].value) - 1);
            kv[kv_count].value[sizeof(kv[0].value) - 1] = '\0';
            kv_count++;
        }
    }

    fclose(f);
    return 0;
}

const char *config_get(const char *key) {
    for (int i = 0; i < kv_count; i++)
        if (strcmp(kv[i].key, key) == 0) return kv[i].value;
    return NULL;
}

int config_feed_count(void) { return feed_count; }

const char *config_feed(int index) {
    return (index >= 0 && index < feed_count) ? feeds[index] : NULL;
}
