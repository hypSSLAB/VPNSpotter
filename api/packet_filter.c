#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/vpn_fingerprint.h"

static int has_consecutive_zero_bits(unsigned char *data, int length, int zero_consecutive) {
    int consecutive = 0;

    for (int i = 0; i < length; i++) {
        unsigned char byte_val = data[i];

        for (int bit = 0; bit < 8; bit++) {
            int bit_val = (byte_val >> bit) & 0x01; 

            if (bit_val == 0) {
                consecutive++;
                if (consecutive >= zero_consecutive) {
                    return PACKET_USED; 
                }
            } else {
                consecutive = 0;
            }
        }
    }

    return PACKET_NOT_USED;
}

static int has_consecutive_zeros_bytes(unsigned char *data, int length, int zero_consecutive)
{
    int consecutive = 0;

    for (int i = 0; i < length; i++) {
        if (data[i] == 0x00) {
            consecutive++;
            if (consecutive >= zero_consecutive) {
                return PACKET_USED;  
            }
        } else {
            consecutive = 0;
        }
    }
    return PACKET_NOT_USED;
}

static int filter_by_zero(struct packet_info *info_list, int zero_consecutive, int nb_application_packet, int nb_bytes_needed) {
    debug("filter_by_zero : %d\n", zero_consecutive);
    
    for (int i = 0; i < nb_application_packet; i++) {
        info_list[i].filter_by_zero = PACKET_NOT_USED;
    }

    for (int i = 0; i < nb_application_packet; i++) {
        int has_run = has_consecutive_zero_bits(info_list[i].payload, nb_bytes_needed, zero_consecutive);
        
        if (has_run == PACKET_USED) {
            info_list[i].filter_by_zero = PACKET_USED;
        }
    }

    return 0;
}

static int filter_by_latency(struct packet_info *info_list, double latency_percentage, int nb_application_packet, int nb_bytes_needed) {
    debug("filter_by_latency: %lf\n", latency_percentage);

    // We still need separate 'before' timestamps for each direction
    // to correctly compute inter-packet latency.
    struct timeval before_src = {0, 0};
    struct timeval before_dst = {0, 0};
    struct timeval diff;
    double timestamp_sec;

    // Temporary arrays to store latencies for each direction separately
    latency_info_t *src_latencies = (latency_info_t *)calloc(nb_application_packet, sizeof(latency_info_t));
    latency_info_t *dst_latencies = (latency_info_t *)calloc(nb_application_packet, sizeof(latency_info_t));

    int src_count = 0;
    int dst_count = 0;

    // 1) Compute the inter-packet latency for each direction
    //    and store them in separate arrays.
    for (int i = 0; i < nb_application_packet; i++) {
        if (info_list[i].direction == SRC_TO_DST) {
            // diff = current_timestamp - before_src
            timeval_subtract(&diff, &info_list[i].timestamp, &before_src);
            timestamp_sec = diff.tv_sec + diff.tv_usec / 1000000.0;

            src_latencies[src_count].latency = timestamp_sec;
            src_latencies[src_count].index   = i;
            src_count++;

            // Update 'before_src'
            before_src = info_list[i].timestamp;
        }
        else if (info_list[i].direction == DST_TO_SRC) {
            // diff = current_timestamp - before_dst
            timeval_subtract(&diff, &info_list[i].timestamp, &before_dst);
            timestamp_sec = diff.tv_sec + diff.tv_usec / 1000000.0;

            dst_latencies[dst_count].latency = timestamp_sec;
            dst_latencies[dst_count].index   = i;
            dst_count++;

            // Update 'before_dst'
            before_dst = info_list[i].timestamp;
        }
    }

    // Comparison function for qsort (ascending order by latency)
    int compare_latency(const void *a, const void *b)
    {
        double l1 = ((latency_info_t *)a)->latency;
        double l2 = ((latency_info_t *)b)->latency;
        if (l1 < l2) return -1;
        if (l1 > l2) return 1;
        return 0;
    }

    // 2) Sort both arrays by latency (ascending order).
    qsort(src_latencies, src_count, sizeof(latency_info_t), compare_latency);
    qsort(dst_latencies, dst_count, sizeof(latency_info_t), compare_latency);

    // 3) Merge the two arrays into one array for unified filtering.
    int total_count = src_count + dst_count;
    latency_info_t *all_latencies = (latency_info_t *)calloc(total_count, sizeof(latency_info_t));

    // Copy src_latencies and dst_latencies into all_latencies
    memcpy(all_latencies, src_latencies, src_count * sizeof(latency_info_t));
    memcpy(all_latencies + src_count, dst_latencies, dst_count * sizeof(latency_info_t));

    // Now sort this merged array
    qsort(all_latencies, total_count, sizeof(latency_info_t), compare_latency);

    // 4) Determine the discard index for the merged array based on latency_percentage.
    //    Example: if total_count=100 and latency_percentage=10 => discard_index=10 (lowest 10 packets).
    int discard_index = (int)((latency_percentage * total_count) / 100.0);
    if (discard_index < 0) discard_index = 0;
    if (discard_index > total_count) discard_index = total_count;

    debug("Merged total_count = %d, discard_index = %d\n", total_count, discard_index);

    // 5) Mark the lowest 'discard_index' packets as PACKET_NOT_USED,
    //    and the rest as PACKET_USED.
    //    This ensures exactly n% of the packets (by count) are discarded,
    //    regardless of direction.
    for (int i = 0; i < total_count; i++) {
        int pkt_index = all_latencies[i].index;
        if (i < discard_index) {
            // Lowest latencies => discard
            info_list[pkt_index].filter_by_latency = PACKET_NOT_USED;
        } else {
            // Keep the rest
            info_list[pkt_index].filter_by_latency = PACKET_USED;
        }
    }

    // Free the temporary arrays
    free(src_latencies);
    free(dst_latencies);
    free(all_latencies);

    return 0;
}


static int get_needed_bytes(uint32_t val) {
    if (val <= 0xFF) {
        return 1;
    } else if (val <= 0xFFFF) {
        return 2;
    } else if (val <= 0xFFFFFF) {
        return 3;
    } else {
        return 4;
    }
}

static uint32_t read_big_endian(const uint8_t *buf, int size) {
    uint32_t result = 0;
    for (int i = 0; i < size; i++) {
        result = (result << 8) | buf[i];
    }
    return result;
}

static uint32_t read_little_endian(const uint8_t *buf, int size) {
    uint32_t result = 0;
    for (int i = size - 1; i >= 0; i--) {
        result = (result << 8) | buf[i];
    }
    return result;
}

static int has_length(const uint8_t *payload, int nb_bytes_needed, uint32_t actual_len) {
    int threshold_diff = 8; 
    int needed_bytes = get_needed_bytes(actual_len);

    // debug("has length\n");

    for (int offset = 0; offset <= nb_bytes_needed - needed_bytes; offset++) {

        uint32_t val_be = read_big_endian(&payload[offset], needed_bytes);
        if ((val_be > actual_len) ? (val_be - actual_len <= threshold_diff)
                                  : (actual_len - val_be <= threshold_diff)) {
            return PACKET_USED;
        }

        uint32_t val_le = read_little_endian(&payload[offset], needed_bytes);
        if ((val_le > actual_len) ? (val_le - actual_len <= threshold_diff)
                                  : (actual_len - val_le <= threshold_diff)) {
            return PACKET_USED;
        }
    }

    return PACKET_NOT_USED;
}

static int filter_by_length(struct packet_info *info_list, int nb_application_packet, int nb_bytes_needed) {
    debug("filter_by_length\n");

    for (int i = 0; i < nb_application_packet; i++) {
        uint32_t actual_len = (uint32_t)info_list[i].payload_length;
        uint8_t *payload = info_list[i].payload;

        info_list[i].filter_by_length = has_length(payload, nb_bytes_needed, actual_len);
    }
    return 0;
}

int filter_packets(struct packet_info *info_list, struct filter_info *filter, int nb_application_packet, int nb_packets_needed, int nb_bytes_needed) {
    int nb_filter_satisfied;
    int nb_packet_satisfied_src;
    int nb_packet_satisfied_dst;
    
    if (info_list[0].transport_protocol == IPPROTO_UDP) {
        debug("It's for TCP segmentation\n");
        return 0;
    }

    if (filter->enable_latency_filter) {
        filter_by_latency(info_list, filter->latency_percentage, nb_application_packet, nb_bytes_needed);
    }

    if (filter->enable_length_filter) {
        filter_by_length(info_list, nb_application_packet, nb_bytes_needed);
    } 

    if (filter->enable_zero_filter) {
        filter_by_zero(info_list, filter->zero_consecutive, nb_application_packet, nb_bytes_needed);
    }

    nb_packet_satisfied_src = 0;
    nb_packet_satisfied_dst = 0;
    for (int i = 0; i < nb_application_packet; i++) {
        nb_filter_satisfied = 0;

        if (filter->enable_latency_filter) {
            nb_filter_satisfied += info_list[i].filter_by_latency;
        }
        if (filter->enable_length_filter) {
            nb_filter_satisfied += info_list[i].filter_by_length;
        }
        if (filter->enable_zero_filter) {
            nb_filter_satisfied += info_list[i].filter_by_zero;
        }

        if (nb_filter_satisfied >= filter->nb_filter_needed) {
            info_list[i].packet_segmented = PACKET_USED;

            if (info_list[i].direction == SRC_TO_DST) {
                nb_packet_satisfied_src++;
            } else {
                nb_packet_satisfied_dst++;
            }
        } else {
            info_list[i].packet_segmented = PACKET_NOT_USED;
        }        
    }

    debug("nb_packet_satisfied_src : %d\n", nb_packet_satisfied_src);
    debug("nb_packet_satisfied_dst : %d\n", nb_packet_satisfied_dst);

    // SRC_TO_DST
    // DST_TO_SRC
    if (nb_packet_satisfied_src >= nb_packets_needed) {
        info_list[0].total_direction = SRC_TO_DST;
    } else if (nb_packet_satisfied_dst >= nb_packets_needed) {
        info_list[0].total_direction = DST_TO_SRC;
    } else {
        error("not enough filtered packets (filtered : %d, %d, needed : %d)\n", nb_packet_satisfied_src, nb_packet_satisfied_dst, nb_packets_needed);
        return -1;
    }

    return 0;
}

// int count_filtered_packets(struct packet_info *info_list, int nb_packet) {
//     int src_filtered_packets[NB_FILTER_MAX+1];
//     int dst_filtered_packets[NB_FILTER_MAX+1];
//     int nb_filter_passed;

//     for (int i = 0; i < NB_FILTER_MAX+1; i++) {
//         src_filtered_packets[i] = 0;
//         dst_filtered_packets[i] = 0;
//     }

//     for (int i = 0; i < nb_packet; i++) {
//         if (enable_latency_filter == 0 && enable_length_filter == 0 && enable_zero_filter == 0) {
//             continue;
//         }

//         nb_filter_passed = 0;

//         if (enable_latency_filter && info_list[i].filter_by_latency == PACKET_USED) {
//             nb_filter_passed++;
//         }

//         if (enable_length_filter && info_list[i].filter_by_length == PACKET_USED) {
//             nb_filter_passed++;
//         }

//         if (enable_zero_filter && info_list[i].filter_by_zero == PACKET_USED) {
//             nb_filter_passed++;
//         }

//         info_list[i].nb_filter_passed = nb_filter_passed;

//         if (info_list[i].direction == SRC_TO_DST) {
//             src_filtered_packets[nb_filter_passed]++;
//         } else {
//             dst_filtered_packets[nb_filter_passed]++;
//         }
//     }

//     info_list[0].nb_filter_applied = 0;
//     for (int i = 0; i < NB_FILTER_MAX+1; i++) {
//         debug("nb_filtered[%d] = src : %d, dst : %d", i, src_filtered_packets[i], dst_filtered_packets[i]);
//         if (src_filtered_packets[i] > PACKET_WINDOW_SIZE || dst_filtered_packets[i] > PACKET_WINDOW_SIZE) {
//             debug(" applied\n");
//             info_list[0].nb_filter_applied = i;
//             if (src_filtered_packets[i] > dst_filtered_packets[i]) {
//                 info_list[0].total_direction = SRC_TO_DST;
//             } else {
//                 info_list[0].total_direction = DST_TO_SRC;
//             }
//         } else {
//             debug(" not applied\n");
//         }
//     }

//     // if (src_filtered_packets < PACKET_WINDOW_SIZE && dst_filtered_packets < PACKET_WINDOW_SIZE) {
//     //     debug("filter not applied -> src : %d, dst : %d, dir : %d\n", src_filtered_packets, dst_filtered_packets, info_list[0].total_direction);
//     //     info_list[0].filter_applied = 0;
//     // } else {
//     //     info_list[0].filter_applied = 1;
        
//     //     if (src_filtered_packets > dst_filtered_packets) {
//     //         info_list[0].total_direction = SRC_TO_DST;
//     //     } else {
//     //         info_list[0].total_direction = DST_TO_SRC;
//     //     }

//     //     debug("filter applied -> src : %d, dst : %d, dir : %d\n", src_filtered_packets, dst_filtered_packets, info_list[0].total_direction);
//     // }

//     return 0;
// }

int count_filtered_openvpn(char *filename, struct packet_info *info_list, int nb_application_count) {
    int control_channel_count, data_channel_count;
    int fragmented_control_channel_count, fragmented_data_channel_count;
    int encrypted_payload_count;
    int unknown;

    int tcp_length;
    int openvpn_length;
    int opcode;

    int filter_latency;
    int filter_zero;

    control_channel_count = 0;
    data_channel_count = 0;
    fragmented_control_channel_count = 0;
    fragmented_data_channel_count = 0;
    encrypted_payload_count = 0;
    unknown = 0;

    for (int i = 0; i < nb_application_count; i++) {

        if (info_list[i].packet_segmented == PACKET_NOT_USED) {
            continue;
        }

        // if (info_list[i].direction != DST_TO_SRC) {
        //     continue;
        // }

        tcp_length = info_list[i].openvpn.payload_length;
        openvpn_length = info_list[i].openvpn.openvpn_length;
        opcode = info_list[i].openvpn.opcode;

        if (opcode == 9) {
            if (info_list[i].payload[3] == 0 && info_list[i].payload[6] == 0) {
                data_channel_count++;
            } else {
                encrypted_payload_count++;
                // debug("case 1 info_list[%d %d] : ", i, info_list[i].packet_count);
                // for (int j = 0; j < 32; j++) {
                //     debug("%x ", info_list[i].payload[j]);
                // }
                // debug("\n");
                // debug("tcp_length : %d, openvpn_length : %d, opcode : %d\n", tcp_length, openvpn_length, opcode);
            }
        } else if (opcode > 0 && opcode < 9) {
            if (info_list[i].payload[3] == 0 && info_list[i].payload[6] == 0) {
                control_channel_count++;
            } else {
                encrypted_payload_count++;
                // debug("case 2 info_list[%d %d] : ", i, info_list[i].packet_count);
                // for (int j = 0; j < 32; j++) {
                //     debug("%x ", info_list[i].payload[j]);
                // }
                // debug("\n");
                // debug("tcp_length : %d, openvpn_length : %d, opcode : %d\n", tcp_length, openvpn_length, opcode);
            }
        } else {
            encrypted_payload_count++;
            // debug("case 3 info_list[%d %d] : ", i, info_list[i].packet_count);
            // for (int j = 0; j < 32; j++) {
            //     debug("%x ", info_list[i].payload[j]);
            // }
            // debug("\n");
            // debug("tcp_length : %d, openvpn_length : %d, opcode : %d\n", tcp_length, openvpn_length, opcode);
        }
    }

    debug("encrypted_payload_count : %d\n", encrypted_payload_count);
    debug("data_count : %d\n", control_channel_count+data_channel_count+fragmented_control_channel_count+fragmented_data_channel_count);
    
    debug_log(filename, "%d ", control_channel_count+data_channel_count+fragmented_control_channel_count+fragmented_data_channel_count);
    debug_log(filename, "%d", encrypted_payload_count+unknown);

    return 0;
}

// int filter_noise(char *filename, struct packet_info *info_list, struct classification_result *result_list, int nb_packet, int nb_byte) {
//     uint8_t direction;
//     uint64_t byte_list_count;

//     struct timeval result, before;
//     double timestamp_sec;

//     uint64_t openvpn_count, openvpn_count_filtered;
//     uint64_t notopenvpn_count, notopenvpn_count_filtered;

//     direction = info_list[0].direction_total;

//     // filter by latency
//     FILE *openvpn_ptr = fopen("openvpn_time", "a");
//     FILE *notopenvpn_ptr = fopen("notopenvpn_time", "a");

//     openvpn_count = 0;
//     openvpn_count_filtered = 0;
//     notopenvpn_count = 0;
//     notopenvpn_count_filtered = 0;

//     before.tv_sec = 0;
//     before.tv_usec = 0;

//     for (int i = 0; i < nb_packet; i++) {
//         if (info_list[i].direction == direction) {
//             if (info_list[i].openvpn.openvpn_length == info_list[i].openvpn.payload_length || 
//                 (info_list[i].openvpn.openvpn_length != info_list[i].openvpn.payload_length && info_list[i].openvpn.opcode > 0 && info_list[i].openvpn.opcode < 10)) {
//                 timeval_subtract(&result, &(info_list[i].timestamp), &before);
//                 timestamp_sec = result.tv_sec + result.tv_usec / 1000000.0;

//                 openvpn_count++;
//                 if ((uint64_t)(timestamp_sec * 10000000) < 1) {
//                     openvpn_count_filtered++;
//                 }

//                 before = info_list[i].timestamp;

//                 // fprintf(openvpn_ptr, "%ld\n", (uint64_t)(timestamp_sec * 10000000));
//                 // debug("%.6f\n", timestamp_sec);
//             } else {
//                 timeval_subtract(&result, &(info_list[i].timestamp), &before);
//                 timestamp_sec = result.tv_sec + result.tv_usec / 1000000.0;

//                 notopenvpn_count++;
//                 if ((uint64_t)(timestamp_sec * 10000000) < 1) {
//                     notopenvpn_count_filtered++;
//                 }

//                 before = info_list[i].timestamp;

//                 // fprintf(notopenvpn_ptr, "%ld\n", (uint64_t)(timestamp_sec * 10000000));
//             }
//         }
//     }
//     fprintf(openvpn_ptr, "%s %ld %ld\n", filename, openvpn_count, openvpn_count_filtered);
//     fprintf(notopenvpn_ptr, "%s %ld %ld\n", filename, notopenvpn_count, notopenvpn_count_filtered);

//     return 0;
// }
