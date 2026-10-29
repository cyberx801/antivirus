#ifndef THREADUTIL_H
#define THREADUTIL_H

/**
 * @file threadutil.h
 * @brief Minimal cross-platform threading primitives (Win32 / pthreads).
 */

typedef void *tu_thread_t;
typedef void *tu_mutex_t;
typedef void *tu_cond_t;

int  tu_mutex_init(tu_mutex_t *m);
void tu_mutex_lock(tu_mutex_t m);
void tu_mutex_unlock(tu_mutex_t m);
void tu_mutex_destroy(tu_mutex_t m);

int  tu_cond_init(tu_cond_t *c);
void tu_cond_wait(tu_cond_t c, tu_mutex_t m);
void tu_cond_signal(tu_cond_t c);
void tu_cond_destroy(tu_cond_t c);

int  tu_thread_create(tu_thread_t *t, void *(*fn)(void *), void *arg);
void tu_thread_join(tu_thread_t t);

#endif
