#ifndef CONFIG_H
#define CONFIG_H

/**
 * @file config.h
 * @brief Minimal key=value configuration file loader.
 */

/**
 * @brief Load a key=value config file (lines: "key = value", '#' comments).
 * @param path Path to the config file.
 * @return 0 on success, -1 if the file could not be opened (defaults apply).
 */
int config_load(const char *path);

/** @return the value for a key, or NULL if not set. */
const char *config_get(const char *key);

/** @return number of "feed" entries configured. */
int config_feed_count(void);

/** @return the i-th configured feed URL, or NULL. */
const char *config_feed(int index);

#endif
