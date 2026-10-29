#include "../include/hash.h"
#include "../include/sigdb.h"
#include "../include/config.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d\n", __FILE__, __LINE__); failures++; } } while (0)

static void write_file(const char *path, const char *data) {
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(data, 1, strlen(data), f); fclose(f); }
}

int main(void) {
    /* 1. Hashing correctness for "abc" (known vectors) */
    write_file("test_abc.txt", "abc");
    char md5[MD5_HEX_LEN + 1], sha1[SHA1_HEX_LEN + 1], sha256[SHA256_HEX_LEN + 1];
    CHECK(hash_file_all("test_abc.txt", md5, sha1, sha256) == 0);
    CHECK(strcmp(md5, "900150983cd24fb0d6963f7d28e17f72") == 0);
    CHECK(strcmp(sha1, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);
    CHECK(strcmp(sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    /* 2. Algorithm inference from hex length */
    CHECK(algo_from_hex_len(32) == HASH_ALGO_MD5);
    CHECK(algo_from_hex_len(40) == HASH_ALGO_SHA1);
    CHECK(algo_from_hex_len(64) == HASH_ALGO_SHA256);
    CHECK(algo_from_hex_len(10) == HASH_ALGO_COUNT);

    /* 3. Signature DB load + lookup */
    write_file("test_sigs.txt",
        "900150983cd24fb0d6963f7d28e17f72\n"
        "a9993e364706816aba3e25717850c26c9cd0d89d\n");
    CHECK(sigdb_load("test_sigs.txt") == 0);
    CHECK(sigdb_is_malicious_hex("900150983cd24fb0d6963f7d28e17f72", HASH_ALGO_MD5) == 1);
    CHECK(sigdb_is_malicious_hex("a9993e364706816aba3e25717850c26c9cd0d89d", HASH_ALGO_SHA1) == 1);
    CHECK(sigdb_is_malicious_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", HASH_ALGO_SHA256) == 0);
    sigdb_free();

    /* 4. Config parsing */
    write_file("test_cfg.txt", "threads = 9\nwhitelist = data/wl.txt\nfeed = http://x/h.txt\n");
    CHECK(config_load("test_cfg.txt") == 0);
    CHECK(config_get("threads") && strcmp(config_get("threads"), "9") == 0);
    CHECK(config_get("whitelist") && strcmp(config_get("whitelist"), "data/wl.txt") == 0);
    CHECK(config_feed_count() == 1);
    CHECK(config_feed(0) && strcmp(config_feed(0), "http://x/h.txt") == 0);

    remove("test_abc.txt");
    remove("test_sigs.txt");
    remove("test_sigs.txt.cache");
    remove("test_cfg.txt");

    if (failures) { printf("%d test(s) FAILED\n", failures); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
