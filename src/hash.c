#include "../include/hash.h"
#include <stdio.h>
#include <openssl/sha.h>

/**
 * @brief Calculates the SHA-256 hash of a given file.
 *
 * This function reads the file in 1 KB chunks, updates the hash context,
 * and finally produces a 64-character hexadecimal hash string.
 *
 * @param filename Path to the input file.
 * @param output_hex Pointer to a char buffer with at least 65 bytes.
 *                   (64 hex characters + null terminator)
 * @return 0 on success, -1 on error (e.g. file cannot be opened).
 */
int sha256_of_file(const char *filename, char *output_hex) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;  // File could not be opened
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buffer[1024];
    size_t bytesRead;

    // ✅ spelling fixed: bytesRead (not bytesReaf)
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        SHA256_Update(&ctx, buffer, bytesRead);
    }

    fclose(file);

    // ✅ spelling fixed: unsigned, not unsined
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    // Convert binary hash to hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }

    output_hex[64] = '\0';  // Null-terminate string
    return 0;
}
