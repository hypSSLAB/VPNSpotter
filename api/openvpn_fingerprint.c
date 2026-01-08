#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/openvpn_fingerprint.h"

int parse_pcap_into_openvpn(char *filename, struct sniff_openvpn openvpn_arr[]) {
    struct sniff_ethernet *ethernet;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;
    struct sniff_udp *udp;
    struct sniff_openvpn openvpn;
    uint64_t ip_src, ip_dst;
    char *payload;

    int ethernet_size;
    uint64_t ip_size;
    uint64_t tcp_size;
    uint64_t udp_size;
    uint64_t payload_size;

    const unsigned char *packet;  
    struct pcap_pkthdr *header;
    pcap_t *handler;

    char error_buf[PCAP_ERRBUF_SIZE];
    int openvpn_count;

    if (filename == NULL) {
        debug("ERROR: no pcap input\n");
        return -1;
    }

    //open file and create pcap handler
    handler = pcap_open_offline(filename, error_buf);

    if (handler == NULL) {
        debug("failed to open pcap file\n");
        debug("%s\n", error_buf);
        return -1;
    }

    ethernet_size = 0;
    if (pcap_datalink(handler) != DLT_EN10MB) {
        ethernet_size = SIZE_ETHERNET;
        debug("it is not an Ethernet capture\n");
    }

    // iterate pcap file
    openvpn_count = 0;
    while (pcap_next_ex(handler, &header, &packet) >= 0) {

        if (openvpn_count == SNIFF_OPENVPN_MAX) {
            break;
        }

        // get ethernet
        ethernet = (struct sniff_ethernet *)(packet);

        // get ip
        ip = (struct sniff_ip *)(packet + SIZE_ETHERNET - ethernet_size);
        ip_size = IP_HL(ip)*4;

        if (openvpn_count == 0) {
            ip_src = ip->ip_src.s_addr;
            ip_dst = ip->ip_dst.s_addr;
        }

        // determine tcp or udp
        uint64_t temp_size;

        switch (ip->ip_p) {
        case IPPROTO_TCP:
            tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET - ethernet_size + ip_size);
            tcp_size = TH_OFF(tcp)*4;        
            temp_size = tcp_size;
            openvpn_arr[openvpn_count].transport_protocol = IPPROTO_TCP;
            break;
        case IPPROTO_UDP:
            udp = (struct sniff_udp *)(packet + SIZE_ETHERNET - ethernet_size + ip_size);
            udp_size = ntohs(udp->uh_ulen);
            temp_size = 8;
            openvpn_arr[openvpn_count].transport_protocol = IPPROTO_UDP;
            break;
        default:
            // debug("unknown protocol\n");
            continue;
        }

        // get payload
        payload = (char *)(packet + SIZE_ETHERNET - ethernet_size + ip_size + temp_size);
        payload_size = ntohs(ip->ip_len) - (ip_size + temp_size);

        if (payload_size == 0) {
            continue;
        }

        openvpn_arr[openvpn_count].payload_length = payload_size - 2;
        openvpn_arr[openvpn_count].openvpn_length = get_openvpn_length(payload, ip->ip_p);
        openvpn_arr[openvpn_count].opcode = get_openvpn_opcode(payload, ip->ip_p);
        if (ip->ip_src.s_addr == ip_src) {
            openvpn_arr[openvpn_count].direction = SRC_TO_DST;
        } else {
            openvpn_arr[openvpn_count].direction = DST_TO_SRC;
        }
        openvpn_count++;
    }

    if (openvpn_count < SNIFF_OPENVPN_MAX) {
        debug("the number of packets must be more than %d\n", SNIFF_OPENVPN_MAX);
        pcap_close(handler);
        return -1;
    }

    pcap_close(handler);
    return 0;
}

int opcode_fingerprint_old(struct sniff_openvpn openvpn_arr[]) {
    uint8_t opcode_set[OPCODE_SET_MAX+10];
    uint64_t opcode_set_size;
    uint64_t is_unique;

    opcode_set[0] = openvpn_arr[0].opcode;
    opcode_set[1] = openvpn_arr[1].opcode;
    opcode_set_size = 2;

    if (opcode_set[0] == opcode_set[1]) {
        debug("[0] and [1] are same\n");
        return -1;
    }

    for (uint64_t i = 2; i < SNIFF_OPENVPN_MAX; i++) {
        uint8_t tmp_opcode = openvpn_arr[i].opcode;

        if ((tmp_opcode == opcode_set[0] || tmp_opcode == opcode_set[1]) && opcode_set_size >= 4) {
            debug("same as [0] or [1] and more than %d\n", OPCODE_SET_MIN);
            return -1;
        }

        is_unique = 1;
        for (uint64_t j = 0; j < opcode_set_size; j++) {
            if (tmp_opcode == opcode_set[j]) {
                is_unique = 0;
                break;
            }
        }
        
        if (is_unique) {
            if (opcode_set_size > OPCODE_SET_MAX) {
                debug("more than %d\n", OPCODE_SET_MAX);
                return -1;
            }
            opcode_set[opcode_set_size] = tmp_opcode;
            opcode_set_size++;
        }
    }

    if (opcode_set_size < 4) {
        debug("less than %d\n", OPCODE_SET_MIN);
        return -1;
    }
    
    return 0;
}

int ack_fingerprint_old(struct sniff_openvpn openvpn_arr[]) {
    uint64_t acks[ACK_FINGERPRINT_WINDOW_SIZE];
    uint8_t ack_opcode = openvpn_arr[2].opcode;

    for (uint64_t i = 0; i < ACK_FINGERPRINT_WINDOW_SIZE; i++) {
        acks[i] = 0;
        for (uint64_t j = 0; j < ACK_FINGERPRINT_BIN_SIZE; j++) {
            if (openvpn_arr[i*ACK_FINGERPRINT_WINDOW_SIZE+j].opcode == ack_opcode) {
                acks[i]++;
            }
        }
    }

    for (uint64_t i = 0; i < ACK_FINGERPRINT_WINDOW_SIZE; i++) {
        // 1 <= BIN[1] <= 3
        if (i == 0 && !(acks[i] >= 1 && acks[i] <= 3)) {
            debug("1 <= BIN[1] <= 3\n");
            return -1;
        }

        // 2 <= BIN[2] <= 5
        if (i == 1 && !(acks[i] >= 2 && acks[i] <= 5)) {
            debug("2 <= BIN[2] <= 5\n");
            return -1;
        }

        // BIN[3-5] <= 5
        if ((i >= 2 && i <= 4) && !(acks[i] <= 5)) {
            debug("BIN[3-5] <= 5\n");
            return -1;
        }         

        // BIN[6-N] <= 1
        if (i >= 5 && !(acks[i] <= 1)) {
            debug("BIN[6-N] <= 1\n");
            return -1;
        }
    }
    return 0;
}