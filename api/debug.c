#include "../include/core.h"
#include "../include/debug.h"

#define MAX_DEBUG_FILES 128

typedef struct {
    FILE *file;
    char *path;
    int initialized;
} DebugFile;

static DebugFile debug_files[MAX_DEBUG_FILES] = {0};

static FILE *get_debug_file(const char *file_path) {
    for (int i = 0; i < MAX_DEBUG_FILES; i++) {
        if (debug_files[i].path != NULL && strcmp(debug_files[i].path, file_path) == 0) {
            return debug_files[i].file;
        }
    }

    for (int i = 0; i < MAX_DEBUG_FILES; i++) {
        if (debug_files[i].path == NULL) {
            debug_files[i].file = fopen(file_path, "w");
            if (debug_files[i].file == NULL) {
                fprintf(stderr, "Failed to open debug file '%s': %s\n", file_path, strerror(errno));
                return NULL;
            }
            debug_files[i].path = strdup(file_path);
            debug_files[i].initialized = 1; 
            return debug_files[i].file;
        }
    }

    fprintf(stderr, "Maximum number of debug files (%d) reached\n", MAX_DEBUG_FILES);
    return NULL;
}

static FILE *append_debug_file(const char *file_path) {
    for (int i = 0; i < MAX_DEBUG_FILES; i++) {
        if (debug_files[i].path != NULL && strcmp(debug_files[i].path, file_path) == 0) {
            if (debug_files[i].initialized) {
                return debug_files[i].file;
            } else {
                fclose(debug_files[i].file);
                debug_files[i].file = fopen(file_path, "a");
                if (debug_files[i].file == NULL) {
                    fprintf(stderr, "Failed to open debug file '%s': %s\n", file_path, strerror(errno));
                    return NULL;
                }
                debug_files[i].initialized = 1; 
                return debug_files[i].file;
            }
        }
    }
    return NULL;
}

void debug_with_file(const char *file_path, const char *format, ...) {
    FILE *file = append_debug_file(file_path);
    if (file == NULL) {
        file = get_debug_file(file_path);
    }
    if (file == NULL) {
        return;
    }

    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);

    fflush(file); 
}

__attribute__((destructor)) static void cleanup_debug_files() {
    for (int i = 0; i < MAX_DEBUG_FILES; i++) {
        if (debug_files[i].file != NULL) {
            fclose(debug_files[i].file);
            free(debug_files[i].path);
            debug_files[i].file = NULL;
            debug_files[i].path = NULL;
        }
    }
}