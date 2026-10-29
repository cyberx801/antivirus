#define _POSIX_C_SOURCE 200809L
#include "../include/sigdb.h"
#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>

/* require uthash.h in include/ (single header) */
#include "../include/uthash.h"

/* -------- Configuration -------- */
static const size_t BLOOM_BITS = 14377588UL; /* ~14.38M bits => ~1.72 MB */
#define BLOOM_HASH_COUNT 10 /* k hash functions (double hashing) */

/* -------- Bloom filter data -------- */
static unsigned char *bloom_bits = NULL;
static size_t bloom_bytes = 0;

/* -------- Hash table (uthash) -------- */
typedef struct sig_entry {
    uint8_t key[33];   /* [algo byte][hash bytes], 1 + up to 32 */
    unsigned key_len;  /* 1 + hash length (17 / 21 / 33) */
    UT_hash_handle hh;
} sig_entry_t;

static sig_entry_t *sig_table = NULL;
static size_t loaded_count = 0;

/* -------- Helpers -------- */

static inline void bloom_set_bit(size_t idx) {
    bloom_bits[idx >> 3] |= (1u << (idx & 7));
}

static inline int bloom_get_bit(size_t idx) {
    return (bloom_bits[idx >> 3] >> (idx & 7)) & 1u;
}

/* FNV-1a 64-bit over binary */
static uint64_t fnv1a64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* djb2 variant over binary */
static uint64_t djb2_64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = 5381ULL;
    for (size_t i = 0; i < len; ++i)
        h = ((h << 5) + h) + p[i];
    return h;
}

/* double hashing to generate k indices */
static void bloom_get_indices(const uint8_t *key, size_t key_len, size_t indices[], unsigned k) {
    uint64_t h1 = fnv1a64(key, key_len);
    uint64_t h2 = djb2_64(key, key_len);
    for (unsigned i = 0; i < k; ++i)
        indices[i] = (size_t)((h1 + (uint64_t)i * h2) % BLOOM_BITS);
}

/* hex string -> binary. returns 0 on success */
static int hex2bin(const char *hex, size_t hex_len, uint8_t *out) {
    size_t bin_len = hex_len / 2;
    for (size_t i = 0; i < bin_len; ++i) {
        char a = hex[i * 2];
        char b = hex[i * 2 + 1];
        if (!isxdigit((unsigned char)a) || !isxdigit((unsigned char)b)) return -1;
        uint8_t va = (uint8_t)(isdigit((unsigned char)a) ? a - '0' : (tolower((unsigned char)a) - 'a' + 10));
        uint8_t vb = (uint8_t)(isdigit((unsigned char)b) ? b - '0' : (tolower((unsigned char)b) - 'a' + 10));
        out[i] = (uint8_t)((va << 4) | vb);
    }
    return 0;
}

static unsigned hash_bytes_for_algo(hash_algo_t a) {
    switch (a) {
        case HASH_ALGO_MD5:    return 16;
        case HASH_ALGO_SHA1:   return 20;
        case HASH_ALGO_SHA256: return 32;
        default:               return 0;
    }
}

/* Build the composite key [algo][hash] used for both bloom and uthash. */
static unsigned make_key(const char *hex, hash_algo_t algo, uint8_t key[33]) {
    unsigned hlen = hash_bytes_for_algo(algo);
    if (hex2bin(hex, hlen * 2, key + 1) != 0) return 0;
    key[0] = (uint8_t)algo;
    return 1 + hlen;
}

/* Insert one composite key into the bloom filter and the uthash table. */
static void sigdb_add(const uint8_t *key, unsigned key_len) {
    size_t idxs[BLOOM_HASH_COUNT];
    bloom_get_indices(key, key_len, idxs, BLOOM_HASH_COUNT);
    for (unsigned i = 0; i < BLOOM_HASH_COUNT; ++i)
        bloom_set_bit(idxs[i]);

    sig_entry_t *e = malloc(sizeof(sig_entry_t));
    if (!e) {
        log_warn("Memory alloc failed while loading signature (skipping)");
        return;
    }
    memcpy(e->key, key, key_len);
    e->key_len = key_len;
    HASH_ADD_KEYPTR(hh, sig_table, e->key, e->key_len, e);
    loaded_count++;
}

/* ---------------- persistent cache (binary) ---------------- */

#define CACHE_MAGIC 0x48474344u  /* "HGCD" */
#define CACHE_VERSION 1u

static time_t file_mtime(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_mtime;
}

/* Load signatures from the binary cache into bloom + uthash. Returns 1 on success. */
static int sigdb_load_cache(const char *cache_path) {
    FILE *f = fopen(cache_path, "rb");
    if (!f) return 0;

    uint32_t magic = 0, version = 0;
    uint64_t count = 0;
    if (fread(&magic, sizeof(magic), 1, f) != 1) { fclose(f); return 0; }
    if (fread(&version, sizeof(version), 1, f) != 1) { fclose(f); return 0; }
    if (fread(&count, sizeof(count), 1, f) != 1) { fclose(f); return 0; }

    if (magic != CACHE_MAGIC || version != CACHE_VERSION) {
        fclose(f);
        return 0;
    }

    for (uint64_t i = 0; i < count; i++) {
        uint8_t key_len = 0;
        uint8_t key[33];
        if (fread(&key_len, 1, 1, f) != 1) { fclose(f); return 0; }
        if (key_len < 17 || key_len > 33) { fclose(f); return 0; }
        if (fread(key, 1, key_len, f) != key_len) { fclose(f); return 0; }
        sigdb_add(key, key_len);
    }

    fclose(f);
    return 1;
}

/* Write the in-memory signature set to the binary cache. */
static void sigdb_write_cache(const char *cache_path) {
    FILE *f = fopen(cache_path, "wb");
    if (!f) return;

    uint32_t magic = CACHE_MAGIC;
    uint32_t version = CACHE_VERSION;
    uint64_t count = (uint64_t)loaded_count;
    fwrite(&magic, sizeof(magic), 1, f);
    fwrite(&version, sizeof(version), 1, f);
    fwrite(&count, sizeof(count), 1, f);

    sig_entry_t *cur, *tmp;
    HASH_ITER(hh, sig_table, cur, tmp) {
        uint8_t key_len = (uint8_t)cur->key_len;
        fwrite(&key_len, 1, 1, f);
        fwrite(cur->key, 1, cur->key_len, f);
    }

    fclose(f);
}

/* -------- Public API -------- */

/* Clear any partially-loaded state (used when cache loading fails). */
static void sigdb_reset(void) {
    sig_entry_t *cur, *tmp;
    HASH_ITER(hh, sig_table, cur, tmp) {
        HASH_DEL(sig_table, cur);
        free(cur);
    }
    sig_table = NULL;
    loaded_count = 0;
    if (bloom_bits)
        memset(bloom_bits, 0, bloom_bytes);
}

int sigdb_load(const char *path) {
    if (!path) return -1;

    bloom_bytes = (BLOOM_BITS + 7) >> 3;
    bloom_bits = calloc(bloom_bytes, 1);
    if (!bloom_bits) {
        log_error("Failed to allocate bloom filter (%zu bytes)", bloom_bytes);
        return -1;
    }

    loaded_count = 0;

    char cache_path[1024];
    snprintf(cache_path, sizeof(cache_path), "%s.cache", path);

    /* Use the binary cache only if it is at least as new as the text DB. */
    if (file_mtime(cache_path) >= file_mtime(path)) {
        if (sigdb_load_cache(cache_path)) {
            log_info("Loaded %zu signatures from cache (%s)", loaded_count, cache_path);
            return 0;
        }
        sigdb_reset();
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        log_error("Could not open signature DB: %s", path);
        return -1;
    }

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        size_t len = strlen(line);
        hash_algo_t algo = algo_from_hex_len(len);
        if (algo == HASH_ALGO_COUNT) continue; /* not a valid 32/40/64 hex line */

        uint8_t key[33];
        unsigned key_len = make_key(line, algo, key);
        if (key_len == 0) continue;

        sigdb_add(key, key_len);
    }

    fclose(f);

    sigdb_write_cache(cache_path);
    log_info("Loaded %zu signatures (bloom: %zu bytes, k=%u)", loaded_count, bloom_bytes, BLOOM_HASH_COUNT);
    return 0;
}

int sigdb_is_malicious_hex(const char *hex_hash, hash_algo_t algo) {
    if (!hex_hash || algo == HASH_ALGO_COUNT) return 0;
    if (!bloom_bits) {
        log_warn("Signature DB not loaded");
        return 0;
    }
    if (strlen(hex_hash) != (size_t)hash_bytes_for_algo(algo) * 2) return 0;

    uint8_t key[33];
    unsigned key_len = make_key(hex_hash, algo, key);
    if (key_len == 0) return 0;

    /* quick bloom test */
    size_t idxs[BLOOM_HASH_COUNT];
    bloom_get_indices(key, key_len, idxs, BLOOM_HASH_COUNT);
    for (unsigned i = 0; i < BLOOM_HASH_COUNT; ++i) {
        if (!bloom_get_bit(idxs[i])) return 0; /* definitely not present */
    }

    /* possible present -> exact check in uthash */
    sig_entry_t *found = NULL;
    HASH_FIND(hh, sig_table, key, key_len, found);
    return (found != NULL) ? 1 : 0;
}

void sigdb_free(void) {
    if (bloom_bits) {
        free(bloom_bits);
        bloom_bits = NULL;
    }
    sig_entry_t *cur, *tmp;
    HASH_ITER(hh, sig_table, cur, tmp) {
        HASH_DEL(sig_table, cur);
        free(cur);
    }
    sig_table = NULL;
    loaded_count = 0;
}
