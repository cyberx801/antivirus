#include "../include/scanner.h"
#include "../include/hash.h"
#include "../include/sigdb.h"
#include "../include/logger.h"
#include "../include/report.h"
#include "../include/quarantine.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#define _XOPEN_SOURCE 500  // for nftw()
#include <ftw.h>
#include <sys/stat.h>
#endif

// Global counters shared with the callbacks
static int infected_count = 0;
static int total_count = 0;

/**
 * @brief Hash and check a single regular file, then report/quarantine it.
 */
static void process_file(const char *fpath) {
    total_count++;  // increase total file count

    char hash[65];
    if (sha256_of_file(fpath, hash) != 0) {
        log_message(LOG_WARN, "Could not open file: %s", fpath);
        return;
    }

    // Check against the signature database
    int infected = sigdb_is_malicious(hash);

    // Add result to report.json
    report_add_result(fpath, hash, infected);

    if (infected) {
        log_message(LOG_ERROR, "[INFECTED] %s", fpath);
        infected_count++;
        move_to_quarantine(fpath, hash);
    } else {
        log_message(LOG_INFO, "[CLEAN] %s", fpath);
    }
}

#ifdef _WIN32
/**
 * @brief Recursive directory walk using the Win32 API.
 */
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
            process_file(full);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}
#else
/**
 * @brief Callback function called by nftw() for every file found.
 */
static int scan_file_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag != FTW_F)  // only regular files
        return 0;

    process_file(fpath);
    return 0;
}
#endif

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
    report_start(path);

#ifdef _WIN32
    scan_win_recursive(path);
#else
    if (nftw(path, scan_file_callback, 20, FTW_PHYS) == -1) {
        log_message(LOG_ERROR, "Failed to open directory: %s", path);
        return -1;
    }
#endif

    *total_files = total_count;
    log_message(LOG_INFO, "Scan completed for directory: %s", path);

    return infected_count;
}
