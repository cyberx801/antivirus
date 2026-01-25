
#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/quarantine.h"
static int quarantine_active = 0;  // Global toggle

void quarantine_enable(void) {
    quarantine_active = 1;
    log_message(LOG_INFO, "Quarantine mode enabled.");
    #ifdef _WIN32
    mkdir("quarantine");
    #else
    mkdir("quarantine", 0755);
    #endif
}

void move_to_quarantine(const char *filepath, const char *hash) {
    if (!quarantine_active) return;

    // Extract filename from full path
    const char *filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;

    // New file path in quarantine folder
    char newpath[512];
    snprintf(newpath, sizeof(newpath), "quarantine/%s", filename);

    // Move file (rename is atomic on same filesystem)
    if (rename(filepath, newpath) == 0) {
        log_message(LOG_WARN, "File quarantined: %s → %s", filepath, newpath);
    } else {
        log_message(LOG_ERROR, "Failed to move file to quarantine: %s", filepath);
        return;
    }

    // Log quarantine action
    FILE *logf = fopen("quarantine/log.json", "a");
    if (!logf) {
        log_message(LOG_ERROR, "Failed to open quarantine log file.");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", t);

    fprintf(logf,
        "{ \"file\": \"%s\", \"hash\": \"%s\", \"date\": \"%s\" }\n",
        filename, hash, timestr);

    fclose(logf);
}
