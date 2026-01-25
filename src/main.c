#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../include/logger.h"
#include "../include/sigdb.h"
#include "../include/scanner.h"
#include "../include/report.h"
#include "../include/quarantine.h"
#include "../include/hash.h"
#include "../include/update.h"
#include <curl/curl.h>


#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_WHITE   "\x1b[37m"

void print_banner(void) {
    printf(COLOR_CYAN
        "\n"
        "██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \n"
        "██║  ██║██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗\n"
        "███████║███████║███████╗███████║██║   ██║██║   ██║███████║██████╔╝██║  ██║\n"
        "██╔══██║██╔══██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n"
        "██║  ██║██║  ██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n"
        "╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \n"
        COLOR_RESET);

    printf(COLOR_YELLOW
        "--------------------------------------------------------------------------\n"
        "   🛡️  HASHGUARD v1.0  —  Lightweight Threat Scanner & Updater\n"
        "   Developer : Fatih Özdil\n"
        "   Modules   : Logger | Scanner | SigDB | Update | Quarantine\n"
        "   Build     : %s %s\n"
        "--------------------------------------------------------------------------\n\n"
        COLOR_RESET, __DATE__, __TIME__);
}



// Forward declarations (ileri bildirim)
void print_help(void);
void print_info(void);
void print_summary(int total, int infected, double seconds);
void save_json_report(const char *filename, int total, int infected, double seconds);

// Optional future modules (stubs)
//void update_signatures(void);


int main(int argc, char *argv[]) {

    print_banner();
    log_message(LOG_INFO, "Smart Antivirus CLI starting up...");

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
        log_message(LOG_INFO, "Scanning directory: %s", directory);
        report_start(directory);
        start = clock();
        infected = scan_directory(directory, &total);  // modified scanner
        end = clock();
        elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        report_finish(total, infected, elapsed, "data/report.json");
        // Optional flags
        if (argc > 3) {
            for (int i = 3; i < argc; i++) {
                if (strcmp(argv[i], "--summary") == 0)
                    print_summary(total, infected, elapsed);
                else if (strcmp(argv[i], "--json-report") == 0)
                    save_json_report("data/report.json", total, infected, elapsed);
                else if (strcmp(argv[i], "--quarantine") == 0)
                    quarantine_enable();
            }
        }
    }

    // ----------------------------- CHECK FILE -----------------------------
    else if (strcmp(command, "check") == 0 && argc >= 3) {
        const char *file = argv[2];
        log_message(LOG_INFO, "Checking file: %s", file);
        char hash[65];
        if (sha256_of_file(file, hash) == 0) {
            if (sigdb_is_malicious(hash))
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
    printf("  ./antivirus scan <directory> [--summary] [--json-report] [--quarantine]\n");
    printf("  ./antivirus check <file>\n");
    printf("  ./antivirus update\n");
    printf("  ./antivirus info\n");
    printf("  ./antivirus --help\n\n");
}

void print_info(void) {
    printf("\nSmart Antivirus v1.0 (C version)\n");
    printf("Developer: Fatih Özdil\n");
    printf("Modules: Logger | Scanner | SigDB | Bloom Filter | UTHash\n");
    printf("Signature DB: data/signatures.txt\n");
    printf("Features: CLI, Summary, JSON Report, Quarantine, Update\n\n");
}

void print_summary(int total, int infected, double seconds) {
    printf("\n------ SCAN SUMMARY ------\n");
    printf("Total files scanned: %d\n", total);
    printf("Infected files:      %d\n", infected);
    printf("Clean files:         %d\n", total - infected);
    printf("Scan time:           %.2f seconds\n", seconds);
    printf("--------------------------\n");
}

void save_json_report(const char *filename, int total, int infected, double seconds) {
    FILE *f = fopen(filename, "w");
    if (!f) return;
    fprintf(f,
        "{\n"
        "  \"total_files\": %d,\n"
        "  \"infected\": %d,\n"
        "  \"clean\": %d,\n"
        "  \"scan_time\": %.2f\n"
        "}\n",
        total, infected, total - infected, seconds);
    fclose(f);
    log_message(LOG_INFO, "JSON report saved to %s", filename);
}





