#define _XOPEN_SOURCE 500  // for nftw()
#include "../include/scanner.h"
#include "../include/hash.h"
#include "../include/sigdb.h"
#include "../include/logger.h"
#include "../include/report.h"
#include "../include/quarantine.h"


#include <ftw.h>
#include <stdio.h>
#include <string.h>

// Global counters shared with the callback
static int infected_count = 0;
static int total_count = 0;

/**
 * @brief Callback function called by nftw() for every file found.
 */
static int scan_file_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    if (typeflag != FTW_F)  // only regular files
        return 0;

    total_count++;  // increase total file count

    char hash[65];
    if (sha256_of_file(fpath, hash) != 0) {
        log_message(LOG_WARN, "Could not open file: %s", fpath);
        return 0;
    }

    // Check against the signature database
    int infected = sigdb_is_malicious(hash);

    // Add result to report.json
    report_add_result(fpath, hash, infected);   // ✅ new line

    if (infected) {
        log_message(LOG_ERROR, "[INFECTED] %s", fpath);
        infected_count++;
        move_to_quarantine(fpath, hash);
    } else {
        log_message(LOG_INFO, "[CLEAN] %s", fpath);
    }

    return 0;
}

/**
 * @brief Scans a directory recursively and reports statistics.
 *
 * @param path Directory path to scan.
 * @param total_files Returns the total number of scanned files.
 * @return Number of infected files.
 */
int scan_directory(const char *path, int *total_files) {
    log_message(LOG_INFO, "Starting scan in directory: %s", path);

    infected_count = 0;
    total_count = 0;

    // Start new JSON report session
    report_start(path);   // ✅ new line

    if (nftw(path, scan_file_callback, 20, FTW_PHYS) == -1) {
        log_message(LOG_ERROR, "Failed to open directory: %s", path);
        return -1;
    }

    *total_files = total_count;
    log_message(LOG_INFO, "Scan completed for directory: %s", path);

    return infected_count;
}
