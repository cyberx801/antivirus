#ifndef LOGGER_H
#define LOGGER_H

typedef enum {
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
}LogLevel;

void log_message(LogLevel level, const char *format, ...);

#define log_info(fmt, ...)  log_message(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  log_message(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_message(LOG_ERROR, fmt, ##__VA_ARGS__)


#endif