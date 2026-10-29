#include "../include/threadutil.h"
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>

int tu_mutex_init(tu_mutex_t *m) {
    CRITICAL_SECTION *cs = (CRITICAL_SECTION *)malloc(sizeof(CRITICAL_SECTION));
    if (!cs) return -1;
    InitializeCriticalSection(cs);
    *m = cs;
    return 0;
}
void tu_mutex_lock(tu_mutex_t m)   { EnterCriticalSection((CRITICAL_SECTION *)m); }
void tu_mutex_unlock(tu_mutex_t m) { LeaveCriticalSection((CRITICAL_SECTION *)m); }
void tu_mutex_destroy(tu_mutex_t m) {
    DeleteCriticalSection((CRITICAL_SECTION *)m);
    free(m);
}

int tu_cond_init(tu_cond_t *c) {
    CONDITION_VARIABLE *cv = (CONDITION_VARIABLE *)malloc(sizeof(CONDITION_VARIABLE));
    if (!cv) return -1;
    InitializeConditionVariable(cv);
    *c = cv;
    return 0;
}
void tu_cond_wait(tu_cond_t c, tu_mutex_t m) {
    SleepConditionVariableCS((CONDITION_VARIABLE *)c, (CRITICAL_SECTION *)m, INFINITE);
}
void tu_cond_signal(tu_cond_t c)  { WakeConditionVariable((CONDITION_VARIABLE *)c); }
void tu_cond_destroy(tu_cond_t c) { free(c); }

typedef struct {
    void *(*fn)(void *);
    void *arg;
} win_thread_arg;

static unsigned __stdcall win_thread_start(void *p) {
    win_thread_arg *a = (win_thread_arg *)p;
    a->fn(a->arg);
    free(a);
    return 0;
}

int tu_thread_create(tu_thread_t *t, void *(*fn)(void *), void *arg) {
    win_thread_arg *a = (win_thread_arg *)malloc(sizeof(win_thread_arg));
    if (!a) return -1;
    a->fn = fn;
    a->arg = arg;
    HANDLE h = (HANDLE)_beginthreadex(NULL, 0, win_thread_start, a, 0, NULL);
    if (!h) {
        free(a);
        return -1;
    }
    *t = h;
    return 0;
}
void tu_thread_join(tu_thread_t t) {
    WaitForSingleObject((HANDLE)t, INFINITE);
    CloseHandle((HANDLE)t);
}

#else /* POSIX */

#include <pthread.h>

int tu_mutex_init(tu_mutex_t *m) {
    pthread_mutex_t *mtx = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (!mtx) return -1;
    if (pthread_mutex_init(mtx, NULL) != 0) { free(mtx); return -1; }
    *m = mtx;
    return 0;
}
void tu_mutex_lock(tu_mutex_t m)   { pthread_mutex_lock((pthread_mutex_t *)m); }
void tu_mutex_unlock(tu_mutex_t m) { pthread_mutex_unlock((pthread_mutex_t *)m); }
void tu_mutex_destroy(tu_mutex_t m) {
    pthread_mutex_destroy((pthread_mutex_t *)m);
    free(m);
}

int tu_cond_init(tu_cond_t *c) {
    pthread_cond_t *cv = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
    if (!cv) return -1;
    if (pthread_cond_init(cv, NULL) != 0) { free(cv); return -1; }
    *c = cv;
    return 0;
}
void tu_cond_wait(tu_cond_t c, tu_mutex_t m) {
    pthread_cond_wait((pthread_cond_t *)c, (pthread_mutex_t *)m);
}
void tu_cond_signal(tu_cond_t c)  { pthread_cond_signal((pthread_cond_t *)c); }
void tu_cond_destroy(tu_cond_t c) { pthread_cond_destroy((pthread_cond_t *)c); free(c); }

typedef struct {
    void *(*fn)(void *);
    void *arg;
} posix_thread_arg;

static void *posix_thread_start(void *p) {
    posix_thread_arg *a = (posix_thread_arg *)p;
    a->fn(a->arg);
    free(a);
    return NULL;
}

int tu_thread_create(tu_thread_t *t, void *(*fn)(void *), void *arg) {
    posix_thread_arg *a = (posix_thread_arg *)malloc(sizeof(posix_thread_arg));
    if (!a) return -1;
    a->fn = fn;
    a->arg = arg;
    pthread_t th;
    if (pthread_create(&th, NULL, posix_thread_start, a) != 0) {
        free(a);
        return -1;
    }
    pthread_t *pt = (pthread_t *)malloc(sizeof(pthread_t));
    if (!pt) {
        pthread_detach(th);
        free(a); /* note: arg struct may leak if thread already ran; acceptable for error path */
        return -1;
    }
    *pt = th;
    *t = pt;
    return 0;
}
void tu_thread_join(tu_thread_t t) {
    pthread_join(*(pthread_t *)t, NULL);
    free(t);
}

#endif
