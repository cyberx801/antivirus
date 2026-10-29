#ifndef AI_H
#define AI_H

/**
 * @file ai.h
 * @brief Optional AI-assisted heuristic analysis (offline + optional LLM hook).
 */

typedef struct {
    int verdict;    /* 0 = benign, 1 = suspicious/malicious */
    double score;   /* 0.0 - 100.0 confidence-ish score */
    double entropy; /* Shannon entropy of the file head (0.0 - 8.0), -1 on error */
} ai_result_t;

/**
 * @brief Analyze a file locally (entropy + extension heuristics) and,
 *        if HASHGUARD_AI_URL + HASHGUARD_AI_KEY are set, optionally ask
 *        an OpenAI-compatible LLM to confirm suspicious findings.
 *
 * @param path        Path to the file to analyze.
 * @param sha256_hex  64-char SHA-256 hex string of the file.
 * @return ai_result_t with verdict, score and entropy.
 */
ai_result_t ai_analyze_file(const char *path, const char *sha256_hex);

#endif
