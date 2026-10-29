#include "../include/report.h"
#include "../include/logger.h"
#include "../include/threadutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_RESULTS 10000

static tu_mutex_t report_mtx;
static int report_lock_init = 0;

static void report_lock(void) {
    if (!report_lock_init) {
        tu_mutex_init(&report_mtx);
        report_lock_init = 1;
    }
    tu_mutex_lock(report_mtx);
}

static void report_unlock(void) {
    tu_mutex_unlock(report_mtx);
}

typedef struct {
    char file[512];
    char hash[65];
    int infected;
    int suspicious;
    double ai_score;
    double entropy;
} ScanResult;

static ScanResult results[MAX_RESULTS];
static int result_count = 0;
static char scan_path[512];

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

// Start a new report
void report_start(const char *path) {
    report_lock();
    result_count = 0;
    strncpy(scan_path, path, sizeof(scan_path) - 1);
    scan_path[sizeof(scan_path) - 1] = '\0';
    report_unlock();
}

// Add a file result (thread-safe)
void report_add_result(const char *file, const char *hash, int infected, int suspicious, double ai_score, double entropy) {
    report_lock();
    if (result_count >= MAX_RESULTS) {
        report_unlock();
        return;
    }
    strncpy(results[result_count].file, file, sizeof(results[result_count].file) - 1);
    strncpy(results[result_count].hash, hash, sizeof(results[result_count].hash) - 1);
    results[result_count].infected = infected;
    results[result_count].suspicious = suspicious;
    results[result_count].ai_score = ai_score;
    results[result_count].entropy = entropy;
    result_count++;
    report_unlock();
}

// Finish and write JSON file
void report_finish(int total, int infected, double seconds, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        log_message(LOG_ERROR, "Could not write report file: %s", filename);
        return;
    }

    fprintf(f, "{\n");
    fputs("  \"scan_path\": \"", f);
    json_write_escaped(f, scan_path);
    fputs("\",\n", f);
    fprintf(f, "  \"total_files\": %d,\n", total);
    fprintf(f, "  \"infected\": %d,\n", infected);
    fprintf(f, "  \"clean\": %d,\n", total - infected);
    fprintf(f, "  \"scan_time\": %.2f,\n", seconds);
    fprintf(f, "  \"results\": [\n");

    for (int i = 0; i < result_count; i++) {
        fputs("    {\"file\": \"", f);
        json_write_escaped(f, results[i].file);
        fprintf(f, "\", \"status\": \"%s\", \"hash\": \"%s\", \"ai_score\": %.2f, \"entropy\": %.2f}%s\n",
            results[i].infected ? "INFECTED" : (results[i].suspicious ? "SUSPICIOUS" : "CLEAN"),
            results[i].hash,
            results[i].ai_score,
            results[i].entropy,
            (i == result_count - 1) ? "" : ",");
    }

    fprintf(f, "  ]\n}\n");
    fclose(f);

    log_message(LOG_INFO, "JSON report saved to %s (%d entries)", filename, result_count);
}
