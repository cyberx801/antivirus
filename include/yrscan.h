#ifndef YRSCAN_H
#define YRSCAN_H

/**
 * @file yrscan.h
 * @brief Optional YARA rule scanning (built only when libyara is available).
 */

/**
 * @brief Compile a YARA rules file and scan a single target file.
 *
 * @param rules_path  Path to a .yar rules file.
 * @param target_path Path to the file to scan.
 * @return 0 on success, -1 on error (or when YARA support is absent).
 */
int yrscan_file(const char *rules_path, const char *target_path);

#endif
