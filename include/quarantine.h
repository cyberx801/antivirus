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

#endif