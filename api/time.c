#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/vpn_fingerprint.h"

void timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y) {
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;
}

uint64_t current_time;
uint64_t elapsed_time;

uint64_t get_time(void) {
    uint64_t current_time_tmp;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    current_time_tmp = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    elapsed_time = current_time_tmp - current_time;
    current_time = current_time_tmp;

    return current_time_tmp;
}