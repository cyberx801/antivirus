#ifndef HASH_H
#define HASH_H

#define MD5_HEX_LEN    32
#define SHA1_HEX_LEN   40
#define SHA256_HEX_LEN 64

typedef enum {
    HASH_ALGO_MD5,
    HASH_ALGO_SHA1,
    HASH_ALGO_SHA256,
    HASH_ALGO_COUNT
} hash_algo_t;

/* Single-algorithm helpers (return 0 on success). */
int md5_hex_of_file(const char *filename, char out_hex[MD5_HEX_LEN + 1]);
int sha1_hex_of_file(const char *filename, char out_hex[SHA1_HEX_LEN + 1]);
int sha256_of_file(const char *filename, char out_hex[SHA256_HEX_LEN + 1]);

/* Compute MD5 + SHA1 + SHA256 in a single pass over the file. */
int hash_file_all(const char *filename,
                  char md5[MD5_HEX_LEN + 1],
                  char sha1[SHA1_HEX_LEN + 1],
                  char sha256[SHA256_HEX_LEN + 1]);

/* Map a hex-string length (32/40/64) to an algorithm. */
hash_algo_t algo_from_hex_len(size_t hex_len);

#endif // HASH_H
