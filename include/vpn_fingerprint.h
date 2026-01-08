#ifndef FIELD_H
#define FIELD_H

#include "core.h"
#include "debug.h"
#include "trace_parser.h"

#define NUM_OF_BYTES                    24
#define NUM_OF_PACKETS                  500

#define INITIAL_PACKET_PASSED_SIZE      30
#define PACKET_WINDOW_SIZE              50

#define FILTER_BY_ZERO_WINDOW           2
#define NB_PACKET_MATCHED               5

enum field_type {
    TYPE_STABLE,
    TYPE_INCREMENT,
    TYPE_LENGTH,
    TYPE_HIGH_ENTROPY,
    TYPE_ZERO,
    TYPE_UNKNOWN,
    FIELD_TYPE_SIZE,
};

typedef struct filter_info {
    int enable_zero_filter;
    int enable_latency_filter;
    int enable_length_filter;

    int nb_filter_needed;
    
    double latency_percentage;
    int zero_consecutive;
}filter_info;

typedef struct classification_result {
    uint8_t transport_protocol;
    uint8_t direction;
    int *field_type;
    double **field_prob;
}classification_result;

typedef struct latency_info_t{
    double latency;  
    int index;      
} latency_info_t;

typedef int (*type_classifier)(uint8_t *byte_list, double *prob);
int classify_payload(struct packet_info *info_list, struct classification_result *result_list, int nb_application_count, int nb_packets_needed, int nb_bytes_needed);
// int type_stable_classifier(uint8_t *byte_list, double *prob);
// int type_increment_classifier(uint8_t *byte_list, double *prob);
// int type_length_classifier(uint8_t *byte_list, uint8_t *length_list, double *prob);
// int type_random_classifier(uint8_t *byte_list, double *prob);
// int type_zero_classifier(uint8_t *byte_list, double *prob);

extern int enable_zero_filter;
extern int enable_latency_filter;
extern int enable_length_filter;

typedef int (*packet_filter)(struct packet_info *info_list, int nb_packet, int nb_byte);
int filter_packets(struct packet_info *info_list, struct filter_info *filter, int nb_application_packet, int nb_packets_needed, int nb_bytes_needed);
// int filter_by_latency(struct packet_info *info_list, int nb_application_packet, int nb_bytes_needed);
// int filter_by_zero(struct packet_info *info_list, int nb_application_packet, int nb_bytes_needed);
// int filter_by_length(struct packet_info *info_list, int nb_application_packet, int nb_bytes_needed);
// int has_consecutive_zeros(unsigned char *data, int length, int required_run);
// int has_length(const uint8_t *payload, int nb_bytes_needed, uint32_t actual_len);
int count_filtered_packets(struct packet_info *info_list, int nb_packet);
int count_filtered_openvpn(char *filename, struct packet_info *info_list, int nb_packet);

double calculate_permutation_entropy(uint8_t *sequence, int size, int order);
double calculate_shannon_entropy(uint8_t *sequence, int size);

void timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);
extern uint64_t current_time;
extern uint64_t elapsed_time;

uint64_t get_time(void);

#endif // FIELD_H