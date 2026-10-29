#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "../include/logger.h"
#include "../include/sigdb.h"
#include "../include/scanner.h"
#include "../include/report.h"
#include "../include/quarantine.h"
#include "../include/hash.h"
#include "../include/update.h"
#include "../include/watcher.h"
#include "../include/yrscan.h"
#include "../include/config.h"
#include <curl/curl.h>


#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_WHITE   "\x1b[37m"
#define COLOR_BOLD    "\x1b[1m"
#define COLOR_DIM     "\x1b[2m"

void print_banner(void) {
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN
        "  ██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗\n"
        COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN
        "  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗\n"
        COLOR_RESET);
    printf(COLOR_BOLD COLOR_GREEN
        "  ███████║███████║███████╗███████║██║   ██║██║   ██║███████║██████╔╝██║  ██║\n"
        COLOR_RESET);
    printf(COLOR_BOLD COLOR_BLUE
        "  ██╔══██║██╔══██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n"
        COLOR_RESET);
    printf(COLOR_BOLD COLOR_MAGENTA
        "  ██║  ██║██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n"
        COLOR_RESET);
    printf(COLOR_BOLD COLOR_RED
        "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝\n"
        COLOR_RESET);

    printf(COLOR_YELLOW
        "  ═══════════════════════════════════════════════════════════════════════════\n"
        "   [>]  HashGuard v1.3 — Sentinel  |  Signature intelligence & threat scan\n"
        "  ═══════════════════════════════════════════════════════════════════════════\n"
        COLOR_RESET);

    printf(COLOR_DIM
        "   Developer : Fatih Özdil\n"
        "   Engine    : SHA-256 · Bloom filter · UTHash · cURL · AI heuristics\n"
        "   Modules   : Logger | Scanner | SigDB | Update | Quarantine | AI\n"
        "   Build     : %s %s\n"
        COLOR_RESET, __DATE__, __TIME__);
    printf("\n");
}



// Forward declarations (ileri bildirim)
void print_help(void);
void print_info(void);
void print_summary(int total, int infected, double seconds);

// Optional future modules (stubs)
//void update_signatures(void);


int main(int argc, char *argv[]) {

#ifdef _WIN32
    /* Make the console interpret our UTF-8 output correctly. */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    print_banner();
    log_message(LOG_INFO, "Smart Antivirus CLI starting up...");

    config_load("data/config.txt");

    if (sigdb_load("data/signatures.txt") != 0) {
        log_message(LOG_ERROR, "Failed to load signature database!");
        return 1;
    }

    if (argc < 2) {
        print_help();
        return 0;
    }

    const char *command = argv[1];
    clock_t start, end;
    double elapsed = 0.0;
    int total = 0, infected = 0;

    // ----------------------------- SCAN DIRECTORY -----------------------------
    if (strcmp(command, "scan") == 0 && argc >= 3) {
        const char *directory = argv[2];

        // Parse flags BEFORE scanning so that e.g. --quarantine takes effect.
        int want_summary = 0;
        int threads = 4;
        const char *cfg_threads = config_get("threads");
        if (cfg_threads) threads = atoi(cfg_threads);
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--summary") == 0)
                want_summary = 1;
            else if (strcmp(argv[i], "--quarantine") == 0)
                quarantine_enable();
            else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc)
                threads = atoi(argv[++i]);
        }

        log_message(LOG_INFO, "Scanning directory: %s", directory);
        start = clock();
        infected = scan_directory(directory, &total, threads);  // report_start() is done inside
        end = clock();
        elapsed = (double)(end - start) / CLOCKS_PER_SEC;

        // Always write the detailed JSON report (includes per-file results).
        report_finish(total, infected, elapsed, "data/report.json");

        if (want_summary)
            print_summary(total, infected, elapsed);
    }

    // ----------------------------- CHECK FILE -----------------------------
    else if (strcmp(command, "check") == 0 && argc >= 3) {
        const char *file = argv[2];
        log_message(LOG_INFO, "Checking file: %s", file);
        char md5[MD5_HEX_LEN + 1], sha1[SHA1_HEX_LEN + 1], sha256[SHA256_HEX_LEN + 1];
        if (hash_file_all(file, md5, sha1, sha256) == 0) {
            int infected = sigdb_is_malicious_hex(md5, HASH_ALGO_MD5) ||
                           sigdb_is_malicious_hex(sha1, HASH_ALGO_SHA1) ||
                           sigdb_is_malicious_hex(sha256, HASH_ALGO_SHA256);
            if (infected)
                log_message(LOG_WARN, "⚠️  Threat detected in %s", file);
            else
                log_message(LOG_INFO, "✅ No threats found in %s", file);
        } else {
            log_message(LOG_ERROR, "Failed to read file: %s", file);
        }
    }

    // ----------------------------- UPDATE SIGNATURES -----------------------------
    else if (strcmp(command, "update") == 0) {
        log_message(LOG_INFO, "*** MAIN: update_signatures() IS ABOUT TO RUN ***");
        update_signatures();
        log_message(LOG_INFO, "*** MAIN: update_signatures() FINISHED ***");
    }

    // ----------------------------- RESTORE FROM QUARANTINE -----------------------------
    else if (strcmp(command, "restore") == 0 && argc >= 3) {
        log_message(LOG_INFO, "Restoring file: %s", argv[2]);
        quarantine_restore(argv[2]);
    }

    // ----------------------------- WATCH DIRECTORY -----------------------------
    else if (strcmp(command, "watch") == 0 && argc >= 3) {
        log_message(LOG_INFO, "Entering watch mode for: %s", argv[2]);
        watch_directory(argv[2]);
    }

    // ----------------------------- YARA SCAN -----------------------------
    else if (strcmp(command, "yara") == 0 && argc >= 4) {
        yrscan_file(argv[2], argv[3]);
    }

    // ----------------------------- INFO -----------------------------
    else if (strcmp(command, "info") == 0) {
        print_info();
    }

    // ----------------------------- HELP -----------------------------
    else if (strcmp(command, "--help") == 0) {
        print_help();
    }

    else {
        log_message(LOG_ERROR, "Unknown command: %s", command);
        print_help();
    }

    sigdb_free();
    log_message(LOG_INFO, "Smart Antivirus shutting down...");

    return 0;
}

// ----------------------------- SUPPORT FUNCTIONS -----------------------------

void print_help(void) {
    printf("\nUsage:\n");
    printf("  ./antivirus scan <directory> [--summary] [--quarantine] [--threads N]\n");
    printf("  ./antivirus check <file>\n");
    printf("  ./antivirus update\n");
    printf("  ./antivirus watch <directory>\n");
    printf("  ./antivirus yara <rules.yar> <file>\n");
    printf("  ./antivirus restore <filename>\n");
    printf("  ./antivirus info\n");
    printf("  ./antivirus --help\n\n");
}

void print_info(void) {
    printf("\nSmart Antivirus v1.3 (C version) — Sentinel\n");
    printf("Developer: Fatih Özdil\n");
    printf("Modules: Logger | Scanner | SigDB | Bloom Filter | UTHash | Quarantine | Update | AI | Watcher\n");
    printf("Signature DB: data/signatures.txt (MD5 / SHA-1 / SHA-256)\n");
    printf("Features: CLI, Summary, JSON Report, Quarantine+Restore, Update, AI heuristics, Multi-threaded scan, Whitelist, Watch mode\n\n");
}

void print_summary(int total, int infected, double seconds) {
    printf("\n------ SCAN SUMMARY ------\n");
    printf("Total files scanned: %d\n", total);
    printf("Infected files:      %d\n", infected);
    printf("Clean files:         %d\n", total - infected);
    printf("Scan time:           %.2f seconds\n", seconds);
    printf("--------------------------\n");
}





