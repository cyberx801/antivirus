#include  "../include/logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

void log_message(LogLevel level, const char *format, ...) {
    const char *level_str[]= {"INFO","WARN","ERROR"};


    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char buf[32];
    strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",t);

    printf("[%s] [%s] ", buf, level_str[level]);

    va_list args;
    va_start(args, format);
    vprintf(format,args);
    va_end(args);

    printf("\n");
}