#define _XOPEN_SOURCE 500  // for nftw() on POSIX
#include "../include/scanner.h"
#include "../include/hash.h"
#include "../include/sigdb.h"
#include "../include/logger.h"
#include "../include/report.h"
#include "../include/quarantine.h"
#include "../include/ai.h"
#include "../include/threadutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <ftw.h>
#include <sys/stat.h>
#endif

#define MAX_WORKERS    64
#define QUEUE_CAP      8192
#define MAX_WHITELIST  256

/* ---------------- shared state ---------------- */
static int infected_count = 0;
static int total_count = 0;
static int skipped_count = 0;

static tu_mutex_t counters_mtx;
static tu_mutex_t queue_mtx;
static tu_cond_t  queue_cv;

static char *queue[QUEUE_CAP];
static size_t q_head = 0, q_tail = 0, q_count = 0;

static char whitelist[MAX_WHITELIST][512];
static int whitelist_count = 0;

/* ---------------- helpers ---------------- */

static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void load_whitelist(const char *path) {
    whitelist_count = 0;
    FILE *f = fopen(path, "r");
    if (!f) return; /* no whitelist configured */

    char line[512];
    while (whitelist_count < MAX_WHITELIST && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == '\0') continue;
        strncpy(whitelist[whitelist_count], line, sizeof(whitelist[whitelist_count]) - 1);
        whitelist[whitelist_count][sizeof(whitelist[whitelist_count]) - 1] = '\0';
        whitelist_count++;
    }
    fclose(f);
    if (whitelist_count > 0)
        log_message(LOG_INFO, "Loaded %d whitelist entries from %s", whitelist_count, path);
}

static int is_whitelisted(const char *path) {
    for (int i = 0; i < whitelist_count; i++)
        if (strstr(path, whitelist[i]) != NULL) return 1;
    return 0;
}

/* ---------------- work queue ---------------- */

static int queue_push(char *path) {
    tu_mutex_lock(queue_mtx);
    while (q_count == QUEUE_CAP)
        tu_cond_wait(queue_cv, queue_mtx);
    queue[q_tail] = path;
    q_tail = (q_tail + 1) % QUEUE_CAP;
    q_count++;
    tu_cond_signal(queue_cv);
    tu_mutex_unlock(queue_mtx);
    return 0;
}

/* Returns path, or NULL when a sentinel is reached. */
static char *queue_pop(void) {
    tu_mutex_lock(queue_mtx);
    while (q_count == 0)
        tu_cond_wait(queue_cv, queue_mtx);
    char *p = queue[q_head];
    q_head = (q_head + 1) % QUEUE_CAP;
    q_count--;
    tu_cond_signal(queue_cv);
    tu_mutex_unlock(queue_mtx);
    return p;
}

/* ---------------- per-file processing (worker threads) ---------------- */

static void process_file(const char *fpath) {
    char hash[65];
    if (sha256_of_file(fpath, hash) != 0) {
        log_message(LOG_WARN, "Could not open file: %s", fpath);
        return;
    }

    // Check against the signature database (Bloom filter -> exact UTHash lookup)
    int infected = sigdb_is_malicious(hash);

    // AI-assisted heuristic analysis (entropy + optional LLM hook)
    ai_result_t ai = ai_analyze_file(fpath, hash);
    int suspicious = (!infected && ai.verdict);

    // Add result to report.json (internally synchronized)
    report_add_result(fpath, hash, infected, suspicious, ai.score, ai.entropy);

    tu_mutex_lock(counters_mtx);
    total_count++;
    if (infected) infected_count++;
    tu_mutex_unlock(counters_mtx);

    if (infected) {
        log_message(LOG_ERROR, "[INFECTED] %s", fpath);
        move_to_quarantine(fpath, hash);
    } else if (suspicious) {
        log_message(LOG_WARN, "[SUSPICIOUS] %s (ai score %.0f, entropy %.2f)", fpath, ai.score, ai.entropy);
    } else {
        log_message(LOG_INFO, "[CLEAN] %s", fpath);
    }
}

static void *worker_fn(void *arg) {
    (void)arg;
    for (;;) {
        char *path = queue_pop();
        if (!path) break; /* sentinel */
        process_file(path);
        free(path);
    }
    return NULL;
}

/* ---------------- directory walking (main thread) ---------------- */

static void enqueue_file(const char *path) {
    if (is_whitelisted(path)) {
        log_message(LOG_INFO, "[SKIPPED] %s", path);
        tu_mutex_lock(counters_mtx);
        skipped_count++;
        tu_mutex_unlock(counters_mtx);
        return;
    }
    char *dup = xstrdup(path);
    if (!dup) return;
    queue_push(dup);
}

#ifdef _WIN32
static void scan_win_recursive(const char *path) {
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", path, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_win_recursive(full);
        } else {
            enqueue_file(full);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}
#else
static int scan_file_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag != FTW_F)  // only regular files
        return 0;
    enqueue_file(fpath);
    return 0;
}
#endif

/* ---------------- public API ---------------- */

int scan_directory(const char *path, int *total_files, int threads) {
    if (threads < 1) threads = 1;
    if (threads > MAX_WORKERS) threads = MAX_WORKERS;

    log_message(LOG_INFO, "Starting scan in directory: %s (threads: %d)", path, threads);

    infected_count = 0;
    total_count = 0;
    skipped_count = 0;

    report_start(path);
    load_whitelist("data/whitelist.txt");

    tu_mutex_init(&counters_mtx);
    tu_mutex_init(&queue_mtx);
    tu_cond_init(&queue_cv);

    tu_thread_t workers[MAX_WORKERS];
    int spawned = 0;
    for (int i = 0; i < threads; i++) {
        if (tu_thread_create(&workers[i], worker_fn, NULL) == 0)
            spawned++;
    }

    int walk_failed = 0;
#ifdef _WIN32
    scan_win_recursive(path);
#else
    if (nftw(path, scan_file_callback, 20, FTW_PHYS) == -1) {
        log_message(LOG_ERROR, "Failed to open directory: %s", path);
        walk_failed = 1;
    }
#endif

    /* send one sentinel per worker, then join */
    for (int i = 0; i < spawned; i++)
        queue_push(NULL);
    for (int i = 0; i < spawned; i++)
        tu_thread_join(workers[i]);

    tu_cond_destroy(queue_cv);
    tu_mutex_destroy(queue_mtx);
    tu_mutex_destroy(counters_mtx);

    *total_files = total_count;
    if (skipped_count > 0)
        log_message(LOG_INFO, "Skipped %d whitelisted file(s)", skipped_count);
    log_message(LOG_INFO, "Scan completed for directory: %s", path);

    return walk_failed ? -1 : infected_count;
}
