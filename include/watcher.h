#ifndef WATCHER_H
#define WATCHER_H

/**
 * @file watcher.h
 * @brief Real-time directory monitoring (Win32 ReadDirectoryChangesW / inotify).
 */

/**
 * @brief Monitor a directory for file changes and check new/modified files
 *        against the signature database. Blocks until interrupted.
 *
 * @param path Directory path to watch.
 * @return 0 on clean shutdown, -1 on error.
 */
int watch_directory(const char *path);

#endif
