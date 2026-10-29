#include "../include/logger.h"
#include "../include/quarantine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define make_dir(path) _mkdir(path)
#else
#include <unistd.h>
#define make_dir(path) mkdir(path, 0755)
#endif

static int quarantine_active = 0;  // Global toggle

// Write a string to a FILE with JSON escaping (backslashes, quotes, control chars).
static void json_write_escaped(FILE *f, const char *s) {
    if (!s) return;
    for (const char *p = s; *p; ++p) {
        switch (*p) {
            case '\\': fputs("\\\\", f); break;
            case '"':  fputs("\\\"", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:   fputc(*p, f); break;
        }
    }
}

void quarantine_enable(void) {
    quarantine_active = 1;
    log_message(LOG_INFO, "Quarantine mode enabled.");
    make_dir("quarantine");
}

void move_to_quarantine(const char *filepath, const char *hash) {
    if (!quarantine_active) return;

    // Extract filename from full path (handle both '/' and '\\')
    const char *filename = filepath;
    for (const char *p = filepath; *p; ++p) {
        if (*p == '/' || *p == '\\') filename = p + 1;
    }

    // New file path in quarantine folder
    char newpath[512];
    snprintf(newpath, sizeof(newpath), "quarantine/%s", filename);

    // Move file (rename is atomic on same filesystem)
    if (rename(filepath, newpath) == 0) {
        log_message(LOG_WARN, "File quarantined: %s -> %s", filepath, newpath);
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

    fputs("{ \"file\": \"", logf);
    json_write_escaped(logf, filename);
    fputs("\", \"hash\": \"", logf);
    json_write_escaped(logf, hash);
    fputs("\", \"date\": \"", logf);
    json_write_escaped(logf, timestr);
    fputs("\" }\n", logf);

    fclose(logf);
}

int quarantine_restore(const char *filename) {
    if (!filename || !*filename) {
        log_message(LOG_ERROR, "Restore: no filename given.");
        return -1;
    }

    char src[512];
    snprintf(src, sizeof(src), "quarantine/%s", filename);

    /* Move back to the current working directory; refuse to overwrite. */
    if (rename(src, filename) == 0) {
        log_message(LOG_INFO, "File restored: %s -> %s", src, filename);
        return 0;
    }

    log_message(LOG_ERROR,
        "Failed to restore '%s' (missing from quarantine, or a file with the same name already exists here).",
        filename);
    return -1;
}
