#ifndef SCANNER_H
#define SCANNER_H

/**
 * @brief Scans a directory recursively using a pool of worker threads.
 *
 * @param path        Directory path to scan.
 * @param total_files Returns the total number of scanned files.
 * @param threads     Number of worker threads (clamped to 1..64).
 * @return Number of infected files, or -1 if the directory could not be read.
 */
int scan_directory(const char *path, int *total_files, int threads);

#endif
