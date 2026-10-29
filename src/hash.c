#include "../include/hash.h"
#include <stdio.h>
#include <openssl/evp.h>

/* Write digest bytes as lowercase hex into out (buffer >= 2*digest_len + 1). */
static void bin2hex(const unsigned char *digest, unsigned dlen, char *out) {
    for (unsigned i = 0; i < dlen; i++)
        sprintf(out + i * 2, "%02x", digest[i]);
    out[dlen * 2] = '\0';
}

/* Compute one digest over the whole file (streamed). */
static int digest_hex_of_file(const char *filename, const EVP_MD *md, char *out, unsigned hex_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    fclose(f);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned dlen = 0;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);

    bin2hex(digest, dlen, out);
    out[hex_len] = '\0';
    return 0;
}

int md5_hex_of_file(const char *filename, char out_hex[MD5_HEX_LEN + 1]) {
    return digest_hex_of_file(filename, EVP_md5(), out_hex, MD5_HEX_LEN);
}

int sha1_hex_of_file(const char *filename, char out_hex[SHA1_HEX_LEN + 1]) {
    return digest_hex_of_file(filename, EVP_sha1(), out_hex, SHA1_HEX_LEN);
}

int sha256_of_file(const char *filename, char out_hex[SHA256_HEX_LEN + 1]) {
    return digest_hex_of_file(filename, EVP_sha256(), out_hex, SHA256_HEX_LEN);
}

int hash_file_all(const char *filename,
                  char md5[MD5_HEX_LEN + 1],
                  char sha1[SHA1_HEX_LEN + 1],
                  char sha256[SHA256_HEX_LEN + 1]) {
    FILE *f = fopen(filename, "rb");
    if (!f) return -1;

    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_MD_CTX *s1 = EVP_MD_CTX_new();
    EVP_MD_CTX *s2 = EVP_MD_CTX_new();
    if (!m || !s1 || !s2) {
        if (m) EVP_MD_CTX_free(m);
        if (s1) EVP_MD_CTX_free(s1);
        if (s2) EVP_MD_CTX_free(s2);
        fclose(f);
        return -1;
    }

    EVP_DigestInit_ex(m, EVP_md5(), NULL);
    EVP_DigestInit_ex(s1, EVP_sha1(), NULL);
    EVP_DigestInit_ex(s2, EVP_sha256(), NULL);

    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(m, buf, n);
        EVP_DigestUpdate(s1, buf, n);
        EVP_DigestUpdate(s2, buf, n);
    }
    fclose(f);

    unsigned char d[EVP_MAX_MD_SIZE];
    unsigned dl = 0;

    EVP_DigestFinal_ex(m, d, &dl);  bin2hex(d, dl, md5);
    EVP_DigestFinal_ex(s1, d, &dl); bin2hex(d, dl, sha1);
    EVP_DigestFinal_ex(s2, d, &dl); bin2hex(d, dl, sha256);

    EVP_MD_CTX_free(m);
    EVP_MD_CTX_free(s1);
    EVP_MD_CTX_free(s2);
    return 0;
}

hash_algo_t algo_from_hex_len(size_t hex_len) {
    switch (hex_len) {
        case MD5_HEX_LEN:    return HASH_ALGO_MD5;
        case SHA1_HEX_LEN:   return HASH_ALGO_SHA1;
        case SHA256_HEX_LEN: return HASH_ALGO_SHA256;
        default:             return HASH_ALGO_COUNT; /* unknown */
    }
}
