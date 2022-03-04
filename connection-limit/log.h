// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/*
 * file log.h
 *
 * brief error reporting
 *
 */
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TIMESTAMP_LEN 64
#define DATE_LEN 21

FILE *info;

typedef enum log_level {
    LOG_OFF = 0,
    LOG_DEBUG = 1,
    LOG_INFO = 2,
    LOG_WARN = 3,
    LOG_ERR = 4,
    LOG_CRIT = 5
} log_level_e;

#define LOG_DEBUG_STR "DEBUG"
#define LOG_INFO_STR "INFO"
#define LOG_WARN_STR "WARN"
#define LOG_ERR_STR "ERR"
#define LOG_CRIT_STR "CRIT"

#define DEFAULT_LOGFILE "/var/log/tb/l3af/connection_limit.log"

int verbosity ;

#define log_debug(...) { \
        if (verbosity != LOG_OFF && verbosity <= LOG_DEBUG) { \
            char log_ts[TIMESTAMP_LEN]; \
            log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", LOG_DEBUG_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define log_info(...) { \
        if (verbosity != LOG_OFF && verbosity <= LOG_INFO) { \
            char log_ts[TIMESTAMP_LEN]; \
            log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", LOG_INFO_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define log_warn(...) { \
        if (verbosity != LOG_OFF && verbosity <= LOG_WARN) { \
            char log_ts[TIMESTAMP_LEN]; \
            log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", LOG_WARN_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define log_err(...) { \
        if (verbosity != LOG_OFF && verbosity <= LOG_ERR) { \
            char log_ts[TIMESTAMP_LEN]; \
            log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", LOG_ERR_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

#define log_crit(...) { \
        if (verbosity != LOG_OFF && verbosity <= LOG_CRIT) { \
            char log_ts[TIMESTAMP_LEN]; \
            log_timestamp(log_ts); \
            fprintf(info, "%s: ", log_ts); \
            fprintf(info, "%s: %s: %d: ", LOG_CRIT_STR, __FUNCTION__, __LINE__); \
            fprintf(info, __VA_ARGS__); \
            fprintf(info, "\n"); \
        } \
}

void log_timestamp(char *log_ts);
FILE* set_log_file(void);
#endif /* LOG_H */

