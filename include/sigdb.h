#ifndef SIGDB_H
#define SIGDB_H

#include "hash.h"

/**
 * @file sigdb.h
 * @brief Signature database handler for known malware hashes (MD5/SHA-1/SHA-256).
 */

/**
 * @brief Loads signature database into memory.
 * @param path Path to signature database file (one hash per line, 32/40/64 hex).
 * @return 0 on success, -1 on failure.
 */
int sigdb_load(const char *path);

/**
 * @brief Checks if a given hash is listed as malicious.
 * @param hex_hash hexadecimal hash string (32/40/64 chars).
 * @param algo     the algorithm the hash belongs to.
 * @return 1 if found (malicious), 0 otherwise.
 */
int sigdb_is_malicious_hex(const char *hex_hash, hash_algo_t algo);

/**
 * @brief Frees allocated memory for signature database.
 */
void sigdb_free(void);

#endif
