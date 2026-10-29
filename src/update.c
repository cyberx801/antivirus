#include "update.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir_p(path) _mkdir(path)
#else
#include <unistd.h>
#define mkdir_p(path) mkdir(path, 0755)
#endif

#define MAX_HASHES   200000
#define MAX_FEEDS    4

typedef struct {
    const char *name;
    const char *url;
    const char *cache_path;
    int added_hashes;   // how many valid hashes extracted from this feed
} FeedSource;

// Simple CURL write callback
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

static int ensure_dir(const char *path) {
    struct stat st;
#ifdef _WIN32
    if (stat(path, &st) == 0 && (st.st_mode & _S_IFDIR)) {
#else
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
#endif
        log_message(LOG_INFO, "Directory already exists: %s", path);
        return 0; // already exists
    }
    if (mkdir_p(path) != 0) {
        log_message(LOG_ERROR, "Failed to create directory: %s", path);
        return -1;
    }
    return 0;
}

/**
 * @brief Check if cache file is newer than 'days' days.
 */
static int cache_is_recent(const char *path, int days) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0; // no file -> not recent
    }
    time_t now = time(NULL);
    double diff = difftime(now, st.st_mtime);
    double limit = (double)days * 24 * 60 * 60;
    return diff <= limit; // 1 if recent
}

/**
 * @brief Download a feed to given path using libcurl.
 */
static int download_file(const char *url, const char *out_path) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERROR, "CURL initialization failed.");
        return -1;
    }

    FILE *fp = fopen(out_path, "wb");
    if (!fp) {
        log_message(LOG_ERROR, "Cannot open output file: %s", out_path);
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "HashGuard/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        log_message(LOG_WARN, "Failed to fetch %s: %s",
                    url, curl_easy_strerror(res));
        remove(out_path);
        return -1;
    }

    log_message(LOG_INFO, "Fetched feed: %s", url);
    return 0;
}

/**
 * @brief Extract valid 64-char hex hashes from file into memory.
 */
static int extract_hashes(const char *infile, char hashes[][65], int *count) {
    FILE *fp = fopen(infile, "r");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to open feed file: %s", infile);
        return 0;
    }

    char line[512];
    int added = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;

        // Skip comment/empty
        if (line[0] == '#' || strlen(line) < 64)
            continue;

        // Extract first 64 hex chars only
        char hex[65];
        int pos = 0;

        for (int i = 0; line[i] && pos < 64; i++) {
            if ((line[i] >= '0' && line[i] <= '9') ||
                (line[i] >= 'a' && line[i] <= 'f') ||
                (line[i] >= 'A' && line[i] <= 'F'))
            {
                hex[pos++] = line[i];
            }
        }

        if (pos == 64) {
            if (*count >= MAX_HASHES) break;  // hard cap to prevent buffer overflow
            hex[64] = 0;
            strcpy(hashes[*count], hex);
            (*count)++;
            added++;
        }
    }

    fclose(fp);
    return added;
}

/**
 * @brief Comparator for sorting 65-byte hash strings.
 */
static int cmp_hash(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/**
 * @brief Sort, deduplicate and save final signatures.txt (O(n log n)).
 */
static int save_unique_hashes(char hashes[][65], int count, const char *outfile) {
    FILE *out = fopen(outfile, "w");
    if (!out) {
        log_message(LOG_ERROR, "Failed to open output file for signatures: %s", outfile);
        return 0;
    }

    if (count > 0)
        qsort(hashes, (size_t)count, 65, cmp_hash);

    int unique = 0;
    const char *prev = NULL;
    for (int i = 0; i < count; i++) {
        if (prev && strcmp(prev, hashes[i]) == 0)
            continue;  // duplicate (array is sorted)
        fprintf(out, "%s\n", hashes[i]);
        prev = hashes[i];
        unique++;
    }

    fclose(out);
    return unique;
}

/**
 * @brief Write JSON metadata for feeds and signatures.
 */
static void write_metadata(const FeedSource *feeds, int feed_count,
                           int total_hashes, int unique_hashes,
                           const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        log_message(LOG_WARN, "Failed to write metadata JSON: %s", path);
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", t);

    fprintf(f, "{\n");
    fprintf(f, "  \"generated_at\": \"%s\",\n", timestr);
    fprintf(f, "  \"total_hashes\": %d,\n", total_hashes);
    fprintf(f, "  \"unique_hashes\": %d,\n", unique_hashes);
    fprintf(f, "  \"feeds\": [\n");

    for (int i = 0; i < feed_count; i++) {
        fprintf(f,
            "    { \"name\": \"%s\", \"url\": \"%s\", \"cache\": \"%s\", \"added_hashes\": %d }%s\n",
            feeds[i].name,
            feeds[i].url,
            feeds[i].cache_path,
            feeds[i].added_hashes,
            (i == feed_count - 1) ? "" : ","
        );
    }

    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);

    log_message(LOG_INFO, "Metadata written to %s", path);
}

/**
 * @brief Placeholder for API-based sources (VirusTotal, MISP, OTX, etc.).
 *
 * In the future, you can:
 *  - Read API keys from environment variables (e.g. HASHGUARD_VT_KEY)
 *  - Query REST APIs and append hashes into the 'hashes' array
 */
static void enrich_with_api_sources(char hashes[][65], int *count) {
    (void)hashes;
    (void)count;
    log_message(LOG_INFO,
        "API-based enrichment (VirusTotal/MISP/OTX) is not implemented yet (placeholder).");
}

/**
 * @brief Main update routine: caching + multi-feed + metadata.
 */
void update_signatures(void) {
    log_message(LOG_INFO, "*** UPDATE FUNCTION STARTED ***");
    log_message(LOG_INFO, "Starting threat intelligence update...");

    // Make sure data/cache exists
    ensure_dir("data");
    ensure_dir("data/cache");

    FeedSource feeds[] = {

        {
            "ThreatCluster_SHA256",
            "https://threatcluster.io/api/iocs/public/hashes.txt",
            "data/cache/threatcluster_hashes.txt",
            0
        },

    };

    const int feed_count = sizeof(feeds) / sizeof(feeds[0]);
    char (*hashes)[65] = malloc(sizeof(char[65]) * MAX_HASHES);
    if (!hashes) {
        log_message(LOG_ERROR, "Failed to allocate memory for hashes (MAX_HASHES=%d)", MAX_HASHES);
        return;
    }
    int hash_count = 0;
    int total_added = 0;

    log_message(LOG_INFO, "Using 7-day cache policy for feeds.");

    for (int i = 0; i < feed_count; i++) {
        FeedSource *fs = &feeds[i];

        if (cache_is_recent(fs->cache_path, 7)) {
            log_message(LOG_INFO, "Using cached feed (%s): %s", fs->name, fs->cache_path);
        } else {
            log_message(LOG_INFO, "Cache expired or missing for %s, downloading...", fs->name);
            if (download_file(fs->url, fs->cache_path) != 0) {
                log_message(LOG_WARN, "Skipping %s due to download error.", fs->name);
                continue;
            }
        }

        int added = extract_hashes(fs->cache_path, hashes, &hash_count);
        fs->added_hashes = added;
        total_added += added;
        log_message(LOG_INFO, "%s: %d valid hashes extracted", fs->name, added);
    }

    // API-based enrichment placeholder (VT, MISP, OTX)
    enrich_with_api_sources(hashes, &hash_count);

    if (hash_count == 0) {
        log_message(LOG_WARN, "No valid hashes collected. Keeping old signature DB.");
        return;
    }

    int unique = save_unique_hashes(hashes, hash_count, "data/signatures.txt");
    write_metadata(feeds, feed_count, hash_count, unique, "data/signatures_meta.json");

    log_message(LOG_INFO,
        "Threat intelligence update completed. Total: %d, Unique: %d",
        hash_count, unique);


    free(hashes);


}
