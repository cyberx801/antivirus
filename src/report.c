#include "../include/report.h"
#include "../include/logger.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_RESULTS 10000

typedef struct {
    char file[512];
    char hash[65];
    int infected;
} ScanResult;

static ScanResult results[MAX_RESULTS];
static int result_count = 0;
static char scan_path[512];

// Start a new report
void report_start(const char *path) {
    result_count = 0;
    strncpy(scan_path, path, sizeof(scan_path) - 1);
    scan_path[sizeof(scan_path) - 1] = '\0';
}

// Add a file result
void report_add_result(const char *file, const char *hash, int infected) {
    if (result_count >= MAX_RESULTS) return;
    strncpy(results[result_count].file, file, sizeof(results[result_count].file) - 1);
    strncpy(results[result_count].hash, hash, sizeof(results[result_count].hash) - 1);
    results[result_count].infected = infected;
    result_count++;
}

// Finish and write JSON file
void report_finish(int total, int infected, double seconds, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        log_message(LOG_ERROR, "Could not write report file: %s", filename);
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"scan_path\": \"%s\",\n", scan_path);
    fprintf(f, "  \"total_files\": %d,\n", total);
    fprintf(f, "  \"infected\": %d,\n", infected);
    fprintf(f, "  \"clean\": %d,\n", total - infected);
    fprintf(f, "  \"scan_time\": %.2f,\n", seconds);
    fprintf(f, "  \"results\": [\n");

    for (int i = 0; i < result_count; i++) {
        fprintf(f, "    {\"file\": \"%s\", \"status\": \"%s\", \"hash\": \"%s\"}%s\n",
            results[i].file,
            results[i].infected ? "INFECTED" : "CLEAN",
            results[i].hash,
            (i == result_count - 1) ? "" : ",");
    }

    fprintf(f, "  ]\n}\n");
    fclose(f);

    log_message(LOG_INFO, "JSON report saved to %s (%d entries)", filename, result_count);
}
