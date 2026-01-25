#ifndef SIGDB_H
#define SIGDB_H

/**
 * @file sigdb.h
 * @brief Signature database handler for known malware hashes.
 *
 * Provides functions to load and check malware signature hashes
 * from a local database file (signatures.json or .txt).
 */
/**
 * @brief Loads signature database into memory.
 *
 * @param path Path to signature database file.
 * @return 0 on success, -1 on failure.
 */

int sigdb_load(const char* path);

/**
 * @brief Checks if a given SHA-256 hash is listed as malicious.
 *
 * @param hash 64-character hexadecimal string of SHA-256 hash.
 * @return 1 if hash is found (malicious), 0 otherwise.
 */
int sigdb_is_malicious(const char *hash);

/**
 * @brief Frees allocated memory for signature database.
 */
void sigdb_free(void);

#endif