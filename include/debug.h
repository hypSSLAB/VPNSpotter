#ifndef DEBUG_H
#define DEBUG_H

#include "core.h"

#ifdef DEBUG
#define debug(...) \
            do { fprintf(stderr, __VA_ARGS__); } while (0)
#else
#define debug(...) \
            do {} while (0)
#endif

#ifdef TIME
#define print_time(...) \
            do { fprintf(stdout, __VA_ARGS__); } while (0)
#else
#define print_time(...) \
            do {} while (0)
#endif

#define error(...) \
            do { fprintf(stderr, __VA_ARGS__); } while (0)

#define print(...) \
            do { fprintf(stdout, __VA_ARGS__); } while (0)

void debug_with_file(const char *file_path, const char *format, ...);

#ifdef DEBUG_LOG
#define debug_log(file_path, format, ...) debug_with_file(file_path, format, __VA_ARGS__)
#else
#define debug_log(file_path, format, ...)
#endif

#endif // DEBUG_H


