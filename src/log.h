#ifndef NANOSOCKS_LOG_H
#define NANOSOCKS_LOG_H

enum LogLevel {
    LOG_LEVEL_ERROR   = 0,
    LOG_LEVEL_WARNING = 1,
    LOG_LEVEL_INFO    = 2,
    LOG_LEVEL_DEBUG   = 3,
};

static const enum LogLevel LOG_LEVEL = LOG_LEVEL_DEBUG;

#endif
