#ifndef UPDATE_H
#define UPDATE_H

/**
 * @brief Fetch and update signature database from multiple threat intel feeds.
 *
 * Uses caching (7 days) and writes JSON metadata.
 */
void update_signatures(void);

#endif
