#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/vpn_fingerprint.h"

int stable_ratio = 40;
int increment_ratio = 60;
int length_ratio = 50;
int zero_ratio = 10;

// type_classifier classifier_funcs[] = {
//     type_stable_classifier,
//     type_increment_classifier,
//     NULL, // originally length_classifier
//     type_random_classifier,
//     type_zero_classifier,
//     NULL,
// };

static int type_stable_classifier(uint8_t *byte_list, uint64_t nb_packets_needed, double *prob) {
    uint64_t byte_count[256];
    uint64_t byte_count_max;

    for (int i = 0; i < 256; i++) {
        byte_count[i] = 0;
    }

    for (int i = 0; i < nb_packets_needed; i++) {
        byte_count[byte_list[i]]++;
    }

    byte_count_max = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_count_max < byte_count[i]) {
            byte_count_max = byte_count[i];
        }
    }

    debug("ratio : %ld\n", (byte_count_max * 100 / nb_packets_needed));
    debug("stable : %d\n", stable_ratio);

    if ((byte_count_max * 100 / nb_packets_needed) > stable_ratio) {
        *prob = (double)byte_count_max * 100 / nb_packets_needed;
        debug("return 1\n");
        return 1;
    }

    return 0;
}

static int type_increment_classifier(uint8_t *byte_list, uint64_t nb_packets_needed, double *prob) {
    uint64_t increment_count;
    uint64_t decrement_count;

    increment_count = 0;
    for (int i = 1; i < nb_packets_needed; i++) {
        debug("%x ", byte_list[i]);
        if (byte_list[i] > byte_list[i-1]) {
            increment_count++;
        }
    }
    debug("\n");

    if ((increment_count * 100 / nb_packets_needed) > increment_ratio) {
        *prob = (double)increment_count * 100 / nb_packets_needed;
        return 1;
    }

    return 0;    
}

static int type_length_classifier(uint16_t *byte_list, uint16_t *length_list, uint64_t nb_packets_needed) {
    uint16_t diff_index_big, diff_index_little;
    uint64_t diff_big[65536], diff_little[65536];

    for (int i = 0; i < 32; i++) {
        diff_big[i] = 0;
        diff_little[i] = 0;
    }

    for (int i = 0; i < nb_packets_needed; i++) {
        diff_index_big = length_list[i] - byte_list[i];
        diff_index_little = length_list[i] - ((byte_list[i] >> 8) | (byte_list[i] << 8));

        diff_big[diff_index_big]++;
        diff_little[diff_index_little]++;

        // debug("[%d] diff_index_big : %d, diff_index_little : %d\n", i, diff_index_big, diff_index_little);
    }

    for (int i = 0; i < 32; i++) {
        // debug("[%d] %f\n", i, (double)diff_big[i] * 100 / nb_packets_needed);
        // debug("[%d] %f\n", i, (double)diff_little[i] * 100 / nb_packets_needed);
        if ((diff_big[i] * 100 / nb_packets_needed) >= length_ratio) {
            return 1;
        }
        if ((diff_little[i] * 100 / nb_packets_needed) >= length_ratio) {
            return 1;
        }
    }
    return 0;
}

static int type_random_classifier(uint8_t *byte_list, uint64_t nb_packets_needed, double *prob) {
    const double permutation_threshold = 0.8;
    const double shannon_threshold = 0.5;

    if ((calculate_permutation_entropy(byte_list, nb_packets_needed, 3)) < permutation_threshold) {
        return 0;
    }

    if ((calculate_shannon_entropy(byte_list, nb_packets_needed)) < shannon_threshold) {
        return 0;
    }

    return 1;    
}

// not used
static int type_zero_classifier(uint8_t *byte_list, uint64_t nb_packets_needed, double *prob) {
    uint64_t zero_count;

    return 0;

    zero_count = 0;
    for (int i = 0; i < nb_packets_needed; i++) {
        if (byte_list[i] == 0) {
            zero_count++;
        }
    }

    if ((zero_count * 100 / nb_packets_needed) > zero_ratio) {
        return 1;
    }

    return 0;    
}

int classify_payload(struct packet_info *info_list, struct classification_result *result_list, int nb_application_count, int nb_packets_needed, int nb_bytes_needed) {
    uint64_t byte_list_count;

    result_list->direction = info_list[0].total_direction;
    result_list->transport_protocol = info_list[0].transport_protocol;

    if (result_list->transport_protocol == IPPROTO_TCP) {
        stable_ratio = 40;
        increment_ratio = 70;
        length_ratio = 10;
        zero_ratio = 10;
    } else {
        stable_ratio = 50;
        increment_ratio = 70;
        length_ratio = 70;
        zero_ratio = 50;
    }

    // for (int i = 0; i < 50; i++) {
    //     debug("[%d] %lf %lf\n", i, calculate_shannon_entropy(info_list[i].payload, 16), calculate_permutation_entropy(info_list[i].payload, 16, 3));
    // }

    for (int i = 0; i < nb_bytes_needed; i++) {
        uint8_t *byte_list = (uint8_t *)malloc(sizeof(uint8_t) * nb_packets_needed);

        byte_list_count = 0;
        for (int j = 0; j < nb_application_count; j++) {
            if (byte_list_count == nb_packets_needed) {
                break;
            }
            if (j < INITIAL_PACKET_PASSED_SIZE) {
                continue;
            }
            if (info_list[j].direction != info_list[0].total_direction) {
                continue;
            }
            
            if (info_list[0].transport_protocol == IPPROTO_TCP && info_list[j].packet_segmented == PACKET_NOT_USED) {
                continue;
            }
            
            byte_list[byte_list_count] = info_list[j].payload[i];
            byte_list_count++;
        }

        debug("=====================nb_byte : %d========================\n", i+1);
        result_list->field_type[i] = TYPE_UNKNOWN;

        if (type_increment_classifier(byte_list, nb_packets_needed, &result_list->field_prob[i][TYPE_INCREMENT])) {
            result_list->field_type[i] = TYPE_INCREMENT;
            continue;
        }

        if (type_stable_classifier(byte_list, nb_packets_needed, &result_list->field_prob[i][TYPE_STABLE])) {
            result_list->field_type[i] = TYPE_STABLE;
            continue;
        }

        if (type_zero_classifier(byte_list, nb_packets_needed, &result_list->field_prob[i][TYPE_ZERO])) {
            result_list->field_type[i] = TYPE_ZERO;
            continue;
        }

        if (type_random_classifier(byte_list, nb_packets_needed, &result_list->field_prob[i][TYPE_HIGH_ENTROPY])) {
            result_list->field_type[i] = TYPE_HIGH_ENTROPY;
            continue;
        }

    }

    for (int i = 0; i < nb_bytes_needed-1; i++) {
        uint16_t *byte_list = (uint16_t *)malloc(sizeof(uint16_t) * nb_packets_needed);
        uint16_t *length_list = (uint16_t *)malloc(sizeof(uint16_t) * nb_packets_needed);

        byte_list_count = 0;
        for (int j = 0; j < nb_application_count; j++) {
            if (byte_list_count == nb_packets_needed) {
                break;
            }
            if (j < INITIAL_PACKET_PASSED_SIZE) {
                continue;
            }
            if (info_list[j].direction != info_list[0].total_direction) {
                continue;
            }
            if (info_list[0].transport_protocol == IPPROTO_TCP && info_list[j].packet_segmented == PACKET_NOT_USED) {
                continue;
            }
 
            byte_list[byte_list_count] = info_list[j].payload[i] * 0x100 + info_list[j].payload[i+1];
            length_list[byte_list_count] = info_list[j].payload_length;
            byte_list_count++;
        }

        if (type_length_classifier(byte_list, length_list, nb_packets_needed)) {
            result_list->field_type[i] = TYPE_LENGTH;
            result_list->field_type[i+1] = TYPE_LENGTH;
            break;
        }
    }   

    return 0;
}
