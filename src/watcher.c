#include "../include/watcher.h"
#include "../include/hash.h"
#include "../include/sigdb.h"
#include "../include/ai.h"
#include "../include/logger.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/inotify.h>
#include <unistd.h>
#include <limits.h>
#endif

/* Check a single file and log its verdict (no quarantine in watch mode). */
static void watch_check_file(const char *fullpath) {
    char md5[MD5_HEX_LEN + 1], sha1[SHA1_HEX_LEN + 1], sha256[SHA256_HEX_LEN + 1];
    if (hash_file_all(fullpath, md5, sha1, sha256) != 0)
        return; /* unreadable / directory */

    int infected = sigdb_is_malicious_hex(md5, HASH_ALGO_MD5) ||
                   sigdb_is_malicious_hex(sha1, HASH_ALGO_SHA1) ||
                   sigdb_is_malicious_hex(sha256, HASH_ALGO_SHA256);

    ai_result_t ai = ai_analyze_file(fullpath, sha256);

    if (infected)
        log_message(LOG_ERROR, "[WATCH] [INFECTED] %s", fullpath);
    else if (ai.verdict)
        log_message(LOG_WARN, "[WATCH] [SUSPICIOUS] %s (ai score %.0f, entropy %.2f)", fullpath, ai.score, ai.entropy);
    else
        log_message(LOG_INFO, "[WATCH] [CLEAN] %s", fullpath);
}

#ifdef _WIN32

int watch_directory(const char *path) {
    HANDLE hDir = CreateFileA(
        path, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        log_message(LOG_ERROR, "Cannot open directory for watching: %s", path);
        return -1;
    }

    char buffer[64 * 1024];
    DWORD bytesReturned = 0;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        CloseHandle(hDir);
        return -1;
    }

    log_message(LOG_INFO, "Watching directory: %s (press Ctrl+C to stop)", path);

    int ret = 0;
    while (1) {
        BOOL ok = ReadDirectoryChangesW(
            hDir, buffer, sizeof(buffer), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned, &ov, NULL);
        if (!ok) {
            log_message(LOG_ERROR, "ReadDirectoryChangesW failed.");
            ret = -1;
            break;
        }

        if (WaitForSingleObject(ov.hEvent, INFINITE) != WAIT_OBJECT_0) {
            ret = -1;
            break;
        }

        DWORD offset = 0;
        for (;;) {
            FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)(buffer + offset);

            if (fni->Action == FILE_ACTION_ADDED ||
                fni->Action == FILE_ACTION_MODIFIED ||
                fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {

                char name[MAX_PATH];
                int n = WideCharToMultiByte(CP_UTF8, 0, fni->FileName,
                    (int)(fni->FileNameLength / sizeof(WCHAR)), name, MAX_PATH - 1, NULL, NULL);
                name[n] = '\0';

                char full[MAX_PATH];
                snprintf(full, sizeof(full), "%s\\%s", path, name);
                watch_check_file(full);
            }

            if (fni->NextEntryOffset == 0) break;
            offset += fni->NextEntryOffset;
        }
        ResetEvent(ov.hEvent);
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
    return ret;
}

#else /* POSIX inotify */

int watch_directory(const char *path) {
    int fd = inotify_init();
    if (fd < 0) {
        log_message(LOG_ERROR, "inotify_init failed.");
        return -1;
    }
    if (inotify_add_watch(fd, path, IN_CREATE | IN_MODIFY | IN_MOVED_TO) < 0) {
        log_message(LOG_ERROR, "inotify_add_watch failed for: %s", path);
        close(fd);
        return -1;
    }

    log_message(LOG_INFO, "Watching directory: %s (press Ctrl+C to stop)", path);

    char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
    int ret = 0;
    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) { ret = -1; break; }
        ssize_t i = 0;
        while (i < n) {
            struct inotify_event *ev = (struct inotify_event *)(buf + i);
            if (ev->len > 0 && (ev->mask & (IN_CREATE | IN_MODIFY | IN_MOVED_TO)) && !(ev->mask & IN_ISDIR)) {
                char full[PATH_MAX];
                snprintf(full, sizeof(full), "%s/%s", path, ev->name);
                watch_check_file(full);
            }
            i += sizeof(struct inotify_event) + ev->len;
        }
    }

    close(fd);
    return ret;
}

#endif
