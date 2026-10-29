#define _POSIX_C_SOURCE 200809L
#include "../include/sigdb.h"
#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

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
    uint8_t key[32];       /* binary 32-byte SHA256 */
    UT_hash_handle hh;
} sig_entry_t;

static sig_entry_t *sig_table = NULL;
static size_t loaded_count = 0;

/* -------- Helpers -------- */

/* set bit in bloom */
static inline void bloom_set_bit(size_t idx) {
    bloom_bits[idx >> 3] |= (1u << (idx & 7));
}

/* test bit */
static inline int bloom_get_bit(size_t idx) {
    return (bloom_bits[idx >> 3] >> (idx & 7)) & 1u;
}

/* FNV-1a 64-bit over binary */
static uint64_t fnv1a64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* djb2 variant over binary */
static uint64_t djb2_64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint64_t h = 5381ULL;
    for (size_t i = 0; i < len; ++i)
        h = ((h << 5) + h) + p[i];
    return h;
}

/* double hashing to generate k indices */
static void bloom_get_indices(const uint8_t *key, size_t indices[], unsigned k) {
    uint64_t h1 = fnv1a64(key, 32);
    uint64_t h2 = djb2_64(key, 32);
    uint64_t mod = BLOOM_BITS;
    for (unsigned i = 0; i < k; ++i) {
        uint64_t val = h1 + (uint64_t)i * h2;
        indices[i] = (size_t)(val % mod);
    }
}

/* convert hex (64 chars) to binary 32 bytes. returns 0 on success */
static int hex2bin32(const char *hex, uint8_t *out) {
    if (!hex || !out) return -1;
    for (size_t i = 0; i < 32; ++i) {
        char a = hex[i*2];
        char b = hex[i*2 + 1];
        if (!isxdigit((unsigned char)a) || !isxdigit((unsigned char)b)) return -1;
        uint8_t va = (uint8_t)(isdigit((unsigned char)a) ? a - '0' : (tolower(a) - 'a' + 10));
        uint8_t vb = (uint8_t)(isdigit((unsigned char)b) ? b - '0' : (tolower(b) - 'a' + 10));
        out[i] = (uint8_t)((va << 4) | vb);
    }
    return 0;
}

/* -------- Public API -------- */

int sigdb_load(const char *path) {
    if (!path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) {
        log_error("Could not open signature DB: %s", path);
        return -1;
    }

    /* allocate bloom bitset */
    bloom_bytes = (BLOOM_BITS + 7) >> 3;
    bloom_bits = calloc(bloom_bytes, 1);
    if (!bloom_bits) {
        log_error("Failed to allocate bloom filter (%zu bytes)", bloom_bytes);
        fclose(f);
        return -1;
    }

    /* load lines */
    char line[128];
    loaded_count = 0;
    while (fgets(line, sizeof(line), f)) {
        /* trim newline */
        line[strcspn(line, "\r\n")] = 0;
        /* skip empty or short lines */
        if (strlen(line) != 64) continue;

        uint8_t bin[32];
        if (hex2bin32(line, bin) != 0) continue;

        /* add to bloom */
        size_t idxs[BLOOM_HASH_COUNT];
        bloom_get_indices(bin, idxs, BLOOM_HASH_COUNT);
        for (unsigned i = 0; i < BLOOM_HASH_COUNT; ++i)
            bloom_set_bit(idxs[i]);

        /* add to uthash */
        sig_entry_t *e = malloc(sizeof(sig_entry_t));
        if (!e) {
            log_warn("Memory alloc failed while loading signature (skipping)");
            continue;
        }
        memcpy(e->key, bin, 32);
        HASH_ADD(hh, sig_table, key, 32, e);
        loaded_count++;
    }

    fclose(f);
    log_info("Loaded %zu signatures (bloom: %zu bytes, k=%u)", loaded_count, bloom_bytes, BLOOM_HASH_COUNT);
    return 0;
}

int sigdb_is_malicious_hex(const char *hex_hash) {
    if (!hex_hash) return 0;
    if (!bloom_bits) {
        log_warn("Signature DB not loaded");
        return 0;
    }

    uint8_t bin[32];
    if (hex2bin32(hex_hash, bin) != 0) return 0;

    /* quick bloom test */
    size_t idxs[BLOOM_HASH_COUNT];
    bloom_get_indices(bin, idxs, BLOOM_HASH_COUNT);
    for (unsigned i = 0; i < BLOOM_HASH_COUNT; ++i) {
        if (!bloom_get_bit(idxs[i])) return 0; /* definitely not present */
    }

    /* possible present -> exact check in uthash */
    sig_entry_t *found = NULL;
    HASH_FIND(hh, sig_table, bin, 32, found);
    return (found != NULL) ? 1 : 0;
}

void sigdb_free(void) {
    if (bloom_bits) {
        free(bloom_bits);
        bloom_bits = NULL;
    }
    /* free uthash entries */
    sig_entry_t *cur, *tmp;
    HASH_ITER(hh, sig_table, cur, tmp) {
        HASH_DEL(sig_table, cur);
        free(cur);
    }
    sig_table = NULL;
    loaded_count = 0;
}
int sigdb_is_malicious(const char *hash) {
    return sigdb_is_malicious_hex(hash);
}

