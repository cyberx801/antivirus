#include "../include/ai.h"
#include "../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <curl/curl.h>

#define AI_READ_LIMIT (64u * 1024u)  /* analyze only the first 64 KiB */

/* ------------------------- local helpers ------------------------- */

/* case-insensitive string compare */
static int ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

/* case-insensitive substring search */
static const char *ci_strstr(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *h = hay; *h; h++) {
        size_t i = 0;
        while (i < nl) {
            char c1 = (h[i] >= 'A' && h[i] <= 'Z') ? (char)(h[i] + 32) : h[i];
            char c2 = (needle[i] >= 'A' && needle[i] <= 'Z') ? (char)(needle[i] + 32) : needle[i];
            if (c1 != c2) break;
            i++;
        }
        if (i == nl) return h;
    }
    return NULL;
}

/* risky extensions commonly abused by malware */
static int is_risky_extension(const char *path) {
    static const char *exts[] = {
        ".exe", ".dll", ".scr", ".pif", ".com",
        ".vbs", ".js",  ".ps1", ".bat", ".cmd",
        ".jar", ".msi", ".hta", ".wsf"
    };
    size_t len = strlen(path);
    for (size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
        size_t el = strlen(exts[i]);
        if (len >= el && ieq(path + len - el, exts[i])) return 1;
    }
    return 0;
}

/* Shannon entropy (bits/byte) of the first AI_READ_LIMIT bytes */
static double compute_entropy(const char *path, long *file_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1.0;

    unsigned long long counts[256] = {0};
    unsigned long long total = 0;
    unsigned char buf[4096];
    size_t n;
    while (total < AI_READ_LIMIT && (n = fread(buf, 1, sizeof(buf), f)) > 0) {
        size_t take = (total + n > AI_READ_LIMIT) ? (size_t)(AI_READ_LIMIT - total) : n;
        for (size_t i = 0; i < take; i++) counts[buf[i]]++;
        total += take;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    if (file_size) *file_size = size;

    if (total == 0) return 0.0;

    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!counts[i]) continue;
        double p = (double)counts[i] / (double)total;
        h -= p * (log(p) / log(2.0));
    }
    return h;
}

/* ------------------------- optional LLM hook ------------------------- */

typedef struct {
    char *data;
    size_t len;
} respbuf;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp) {
    respbuf *rb = (respbuf *)userp;
    size_t total = size * nmemb;
    char *nd = (char *)realloc(rb->data, rb->len + total + 1);
    if (!nd) return 0;
    rb->data = nd;
    memcpy(rb->data + rb->len, ptr, total);
    rb->len += total;
    rb->data[rb->len] = '\0';
    return total;
}

static void ensure_curl_init(void) {
    static int done = 0;
    if (!done) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        done = 1;
    }
}

/*
 * Ask an OpenAI-compatible chat-completions API whether the file looks
 * malicious. Returns 1 (malicious), 0 (benign) or -1 (not configured / error).
 */
static int ai_llm_verdict(const char *path, const char *hash, long size, double entropy) {
    const char *url = getenv("HASHGUARD_AI_URL");
    const char *key = getenv("HASHGUARD_AI_KEY");
    const char *model = getenv("HASHGUARD_AI_MODEL");
    if (!url || !*url || !key || !*key) return -1; /* not configured */
    if (!model || !*model) model = "gpt-4o-mini";

    const char *base = strrchr(path, '/');
    const char *bs = strrchr(path, '\\');
    const char *name = path;
    if (base && bs) name = (base > bs ? base : bs) + 1;
    else if (base) name = base + 1;
    else if (bs) name = bs + 1;

    char user_msg[1024];
    snprintf(user_msg, sizeof(user_msg),
        "File name: %s | SHA-256: %s | Size: %ld bytes | Shannon entropy: %.2f. "
        "Is this file likely malicious? Reply with exactly one word: MALICIOUS or BENIGN.",
        name, hash, size, entropy);

    /* strip characters that would break the JSON string */
    char clean[1024];
    size_t j = 0;
    for (size_t i = 0; user_msg[i] && j + 1 < sizeof(clean); i++) {
        if (user_msg[i] == '"' || user_msg[i] == '\\') continue;
        clean[j++] = user_msg[i];
    }
    clean[j] = '\0';

    char payload[4096];
    snprintf(payload, sizeof(payload),
        "{\"model\":\"%s\",\"messages\":["
        "{\"role\":\"system\",\"content\":\"You are a malware triage assistant. Answer with exactly one word: MALICIOUS or BENIGN.\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}],"
        "\"max_tokens\":8,\"temperature\":0}", model, clean);

    ensure_curl_init();
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    respbuf rb = {NULL, 0};

    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, auth);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    int verdict = -1;
    if (rc == CURLE_OK && rb.data) {
        if (ci_strstr(rb.data, "malicious")) verdict = 1;
        else if (ci_strstr(rb.data, "benign")) verdict = 0;
    }
    free(rb.data);
    return verdict;
}

/* ------------------------- public API ------------------------- */

ai_result_t ai_analyze_file(const char *path, const char *sha256_hex) {
    ai_result_t r = {0, 0.0, 0.0};

    long size = 0;
    double ent = compute_entropy(path, &size);
    if (ent < 0.0) {
        r.entropy = -1.0;
        return r; /* unreadable file */
    }
    r.entropy = ent;

    /* local heuristic score */
    double score = 0.0;
    if (ent > 7.5) score += 50.0;
    else if (ent > 7.0) score += 25.0;
    if (is_risky_extension(path) && ent > 7.0) score += 15.0;
    if (score > 100.0) score = 100.0;
    r.score = score;
    r.verdict = (score >= 50.0) ? 1 : 0;

    /* optional LLM confirmation, only for locally suspicious files (cost control) */
    if (r.verdict == 1) {
        int llm = ai_llm_verdict(path, sha256_hex, size, ent);
        if (llm >= 0) {
            r.verdict = llm;
            r.score = llm ? 85.0 : 30.0;
        }
    }

    return r;
}
