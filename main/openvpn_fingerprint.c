#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/vpn_fingerprint.h"
#include "../include/openvpn_fingerprint.h"

#define TYPE_OPCODE     1
#define TYPE_ACK        2

int main(int argc, char *argv[]) {
    char *filename;
    int filtering_type;
    struct sniff_openvpn openvpn_arr[SNIFF_OPENVPN_MAX];
    uint64_t time1;

    if (argc != 3) {
        error("Usage: %s <pcap_file> <opcode|ack>\n", argv[0]);
        return -1;
    }
    filename = argv[1];
    if (strcmp(argv[2], "opcode") == 0) {
        filtering_type = TYPE_OPCODE;
    } else if (strcmp(argv[2], "ack") == 0) {
        filtering_type = TYPE_ACK;
    } else {
        error("ERROR: second argument must be 'opcode' or 'ack'\n");
        return -1;
    }

    // if(check_ip_address(filename)) {
    //     error("ERROR: a pcap file should have 1 unique ip pair\n");
    //     return -1;
    // }

    // if (check_application_count(filename, SNIFF_OPENVPN_MAX)) {
    //     error("ERROR: a pcap file should have more than 100 packtes having payload\n");
    //     return -1;
    // }


    if(parse_pcap_into_openvpn(filename, openvpn_arr)) {
        debug("failed to parse pcap file : %s\n", filename);
        return -1;
    }

    for (int i = 0; i < SNIFF_OPENVPN_MAX; i++) {
        debug("[%d] %d %d %s\n", i, openvpn_arr[i].openvpn_length, openvpn_arr[i].opcode, opcode_to_string(openvpn_arr[i].opcode));
    }

    get_time();

    int result;
    if (filtering_type == TYPE_OPCODE) {
        result = opcode_fingerprint_old(openvpn_arr);
    } else {
        result = ack_fingerprint_old(openvpn_arr);
    }

    get_time();
    time1 = elapsed_time;

    print_time("%ld\n", time1);

    if (result) {
        print("not openvpn\n");
    } else {
        print("openvpn\n");
    }
    return 0;
}
