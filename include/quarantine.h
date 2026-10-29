#ifndef QUARANTINE_H
#define QUARANTINE_H

#include <stdio.h>

/**
 * @brief Enables quarantine mode (called when --quarantine flag is used)
 */
void quarantine_enable(void);

/**
 * @brief Moves a file to the quarantine folder and logs the action.
 */
void move_to_quarantine(const char *filepath, const char *hash);

/**
 * @brief Restores a quarantined file (by name) back to the current directory.
 *
 * @param filename Name of the file inside the quarantine folder.
 * @return 0 on success, -1 if the file is missing or the target exists.
 */
int quarantine_restore(const char *filename);

#endif