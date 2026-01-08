#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/vpn_fingerprint.h"

#define MAX_ARG_LEN     256
#define MAX_FILENAME    1024

char filename[MAX_FILENAME];
int skip_pair_flag = 0;
int nb_packets_needed = PACKET_WINDOW_SIZE;
int nb_bytes_needed = NUM_OF_BYTES;

int enable_zero_filter = 0;
int enable_latency_filter = 0;
int enable_length_filter = 0;

int nb_filter_needed = 0;

typedef struct {
    const char *name;
    int is_mandatory;
    char value[MAX_ARG_LEN];
    int (*handler)(const char *, void *);
} Option;

int handle_input(const char *value, void *ptr) {
    debug("handle_input : %s\n", value);
    strcpy(filename, value);

    return 0;
}

int handle_skip_pair(const char *value, void *ptr) {
    debug("handle_skip_pair : %s\n", value);
    if (value == NULL || (value[0] != '0' && value[0] != '1') || value[1] != '\0') {
        fprintf(stderr, "Error: -skip_check argument must be '0' or '1'. Got '%s'\n", value);
        return -1; 
    }
    skip_pair_flag = value[0] - '0';
    
    return 0;
}

int handle_nb_packet(const char *value, void *ptr) {
    char *endptr;
    int result = (int)strtol(value, &endptr, 10);

    debug("handle_nb_packet : %s\n", value);
    if (*endptr != '\0') {
        fprintf(stderr, "Error: -nb_packet requires numeric value, got '%s'\n", value);
        return -1; 
    }
    nb_packets_needed = result;    

    return 0; 
}

int handle_nb_byte(const char *value, void *ptr) {
    char *endptr;
    int result = (int)strtol(value, &endptr, 10);

    debug("handle_nb_byte : %s\n", value);
    if (*endptr != '\0') {
        fprintf(stderr, "Error: -nb_byte requires numeric value, got '%s'\n", value);
        return -1; 
    }
    nb_bytes_needed = result;    

    return 0; 
}

int handle_filter(const char *value, void *ptr) {
    struct filter_info *filter = (struct filter_info *)(ptr);

    debug("handle_filter : %s\n", value);

    char *copy = strdup(value);
    if (!copy) {
        error("Memory allocation failed\n");
        return -1;
    }

    int filter_count = 0;
    int has_latency = 0, has_zero = 0, has_length = 0;
    int nb_value = -1;

    char *token = strtok(copy, ",");
    char *filters[4];
    int token_count = 0;

    while (token && token_count < 4) {
        filters[token_count++] = token;
        token = strtok(NULL, ",");
    }

    if (token_count == 0) {
        error("Error: -filter must contain at least a numeric value\n");
        free(copy);
        return -1;
    }

    char *endptr;
    nb_value = (int)strtol(filters[token_count - 1], &endptr, 10);
    if (*endptr != '\0' || nb_value < 0 || nb_value > 3) {
        error("Error: invalid numeric filter count: '%s'\n", filters[token_count - 1]);
        free(copy);
        return -1;
    }

    for (int i = 0; i < token_count - 1; i++) {
        if (strcmp(filters[i], "latency") == 0) {
            if (!has_latency) {
                has_latency = 1;
                filter_count++;
            }
        } else if (strcmp(filters[i], "zero") == 0) {
            if (!has_zero) {
                has_zero = 1;
                filter_count++;
            }
        } else if (strcmp(filters[i], "length") == 0) {
            if (!has_length) {
                has_length = 1;
                filter_count++;
            }
        } else {
            error("Error: unknown filter type: '%s'\n", filters[i]);
            free(copy);
            return -1;
        }
    }

    if (nb_value > filter_count) {
        error("Error: filter count (%d) exceeds number of enabled filters (%d)\n", nb_value, filter_count);
        free(copy);
        return -1;
    }

    filter->enable_latency_filter = has_latency;
    filter->enable_zero_filter = has_zero;
    filter->enable_length_filter = has_length;
    filter->nb_filter_needed = nb_value;

    debug("latency=%d, zero=%d, length=%d, nb_filter_needed=%d\n",
          enable_latency_filter, enable_zero_filter, enable_length_filter, nb_filter_needed);

    free(copy);
    return 0;
}

int handle_latency(const char *value, void *ptr) {
    struct filter_info *filter = (struct filter_info *)(ptr);
    char *endptr;

    double result = strtod(value, &endptr);
    if (*endptr != '\0') {
        fprintf(stderr, "Error: -latency requires a numeric value, got '%s'\n", value);
        return -1;
    }

    if (result < 0.0 || result > 100.0) {
        fprintf(stderr, "Error: -latency must be between 0.0 and 100.0, got '%f'\n", result);
        return -1;
    }

    filter->latency_percentage = result;
    return 0;
}

int handle_zero(const char *value, void *ptr) {
    struct filter_info *filter = (struct filter_info *)(ptr);
    char *endptr;

    int result = (int)strtol(value, &endptr, 10);

    filter->zero_consecutive = result;

    return 0;
}

Option options[] = {
    {"input", 1, "", handle_input},
    {"skip_check", 0, "", handle_skip_pair},
    {"nb_packet", 0, "", handle_nb_packet},
    {"nb_byte", 0, "", handle_nb_byte},
    {"filter", 0, "", handle_filter},
    {"latency", 0, "", handle_latency},
    {"zero", 0, "", handle_zero},    
};

const int num_options = sizeof(options) / sizeof(Option);

void usage(char *prog_name) {
    error("Usage: %s", prog_name);
    for (int i = 0; i < num_options; i++) {
        if (options[i].is_mandatory) {
            error(" -%s=<value>", options[i].name);
        } else {
            error(" [-%s=<value>]", options[i].name);
        }
    }
    error("\n");
    exit(EXIT_FAILURE);
}

void parse_arguments(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        int recognized = 0;
        for (int j = 0; j < num_options; j++) {
            int len = strlen(options[j].name);
            if (strncmp(argv[i] + 1, options[j].name, len) == 0 && argv[i][len + 1] == '=') {
                strncpy(options[j].value, argv[i] + len + 2, MAX_ARG_LEN - 1);
                recognized = 1;
                break;
            }
        }
        if (!recognized) {
            error("Unknown argument: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    // check essential options
    for (int i = 0; i < num_options; i++) {
        if (options[i].is_mandatory && strlen(options[i].value) == 0) {
            error("-%s argument is mandatory.\n", options[i].name);
            usage(argv[0]);
        }
    }
}

int main(int argc, char *argv[]) {
    struct packet_info *info_list;
    struct classification_result result_list;
    struct filter_info filter;

    uint64_t time1, time2, time3;
    int nb_application_packet;

    filter.enable_latency_filter = 1;
    filter.enable_length_filter = 1;
    filter.enable_zero_filter = 1;
    filter.nb_filter_needed = 2;
    filter.latency_percentage = 40;
    filter.zero_consecutive = 16;

    parse_arguments(argc, argv);
    
    for (int i = 0; i < num_options; i++) {
        if (strlen(options[i].value) > 0) {
            if (options[i].handler(options[i].value, &filter)) {
                return -1;
            }            
        }
    }

    debug("filename : %s\n", filename);
    debug("skip_pair_flag : %d\n", skip_pair_flag);
    debug("nb_packets_needed : %d\n", nb_packets_needed);
    debug("nb_bytes_needed : %d\n", nb_bytes_needed);

    if (skip_pair_flag == 0 && check_ip_address(filename)) {
        error("ERROR: a pcap file should have 1 unique ip pair\n");
        return -1;
    }

    if ((nb_application_packet = check_application_count(filename)) == -1) {
        error("ERROR: failed to get application layer count\n");
        return -1;
    }

    debug("nb_application_count : %d\n", nb_application_packet);
    if (nb_application_packet < nb_packets_needed) {
        error("ERROR: not enough packets (needed : %d, actual : %d)\n", nb_packets_needed, nb_application_packet);
        return -1;
    }

    info_list = (struct packet_info *)malloc(sizeof(struct packet_info) * nb_application_packet);
    for (int i = 0; i < nb_application_packet; i++) {
        info_list[i].payload = (uint8_t *)malloc(sizeof(uint8_t) * nb_application_packet);
    }

    // result_list.field_type = (int **)malloc(sizeof(int *) * nb_bytes_needed);
    result_list.field_type = (int *)malloc(sizeof(int) * nb_bytes_needed);
    result_list.field_prob = (double **)malloc(sizeof(double *) * nb_bytes_needed);
    for (int i = 0; i < nb_bytes_needed; i++) {
        // result_list.field_type[i] = (int *)malloc(sizeof(int) * FIELD_TYPE_SIZE);
        result_list.field_prob[i] = (double *)malloc(sizeof(double) * FIELD_TYPE_SIZE);
    }

    get_time();

    if (parse_pcap_into_packet_info(filename, info_list, nb_application_packet, nb_bytes_needed)) {
        error("failed to parse pcap file : %s\n", filename);
        return -1;
    }

    get_time();
    time1 = elapsed_time;

    if (nb_application_packet > 5000) {
        nb_application_packet = 5000;
    }

    if (filter_packets(info_list, &filter, nb_application_packet, nb_packets_needed, nb_bytes_needed)) {
        error("failed to filter\n");
        return -1;
    }    
    debug("total_direction : %d\n", info_list[0].total_direction);

    get_time();
    time2 = elapsed_time;

    // if (count_filtered_packets(info_list, nb_packet)) {
    //     return -1;
    // }

    // count_filtered_openvpn("tmp.txt", info_list, nb_application_packet);
    // debug_log("tmp.txt", "\n", 3);

    if (classify_payload(info_list, &result_list, nb_application_packet, nb_packets_needed, nb_bytes_needed)) {
        debug("failed to classify payload : %s\n", filename);
        return -1;
    }

    get_time();
    time3 = elapsed_time;

    char *token_buffer = (char *)malloc(sizeof(char) * (nb_bytes_needed*2 + 1));
    memset(token_buffer, 0, (nb_bytes_needed*2 + 1));
    int buf_index = 0;

    for (int i = 0; i < nb_bytes_needed; i++) {
        const char *token = "N";

        switch(result_list.field_type[i]) {
        case TYPE_LENGTH:
            token = "L";    
            break;
        case TYPE_ZERO:
            token = "Z";
            break;
        case TYPE_STABLE:
            token = "S";
            break;
        case TYPE_INCREMENT:
            token = "I";
            break;
        case TYPE_HIGH_ENTROPY:
            token = "R";
            break;
        case TYPE_UNKNOWN:
            token = "U";
            break;
        }

        int written = snprintf(&token_buffer[buf_index], (nb_bytes_needed*2 + 1) - buf_index, "%s ", token);
        buf_index += written;
    }

    print("%s", token_buffer);

    print_time("; ");
    print_time("%ld ", time1);
    print_time("%ld ", time2);
    print_time("%ld", time3);

    print("\n");

    // // for (int i = 0; i < nb_byte; i++) {

    // //     if (result_list.field_type[i][2]) {
    // //         debug("%.1lf ", result_list.field_prob[i][2]);
    // //         continue;
    // //     }

    // //     if (result_list.field_type[i][1]) {
    // //         debug("%.1lf ", result_list.field_prob[i][1]);
    // //         continue;
    // //     }

    // //     if (result_list.field_type[i][0]) {
    // //         debug("%.1lf ", result_list.field_prob[i][0]);
    // //         continue;
    // //     }

    // //     if (result_list.field_type[i][3]) {
    // //         debug("%.1lf ", result_list.field_prob[i][3]);
    // //         continue;
    // //     }

    // //     if (result_list.field_type[i][4]) {
    // //         debug("%.1lf ", result_list.field_prob[i][4]);
    // //         continue;
    // //     }
        
    // //     debug("%.1lf ", (double)0);
    // // }
    // // debug("\n");

    // // for (int i = 0; i < nb_packet; i++) {
    // //     debug("[%d] ", i+1);
    // //     if (info_list[i].transport_protocol == IPPROTO_TCP) {
    // //         debug("TCP ");
    // //     } else {
    // //         debug("UDP ");
    // //     }
    // //     debug("%lu ", info_list[i].payload_length);
        
    // //     if (info_list[i].direction == SRC_TO_DST) {
    // //         debug("SRC ");
    // //     } else {
    // //         debug("DST ");
    // //     }

    // //     for (int j = 0; j < nb_byte; j++) {
    // //         if (j >= info_list[i].payload_length) {
    // //             debug("null ");
    // //             continue;
    // //         }
    // //         debug("%02x ", info_list[i].payload[j]);
    // //     }
    // //     debug("\n");  
    // // }
    
    return 0;
}
