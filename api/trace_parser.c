#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/vpn_fingerprint.h"

int check_ip_address(char *filename) {
    struct sniff_ip *ip;
    uint64_t ip_src, ip_dst;

    const unsigned char *packet;  
    struct pcap_pkthdr *header;
    pcap_t *handler;

    char error_buf[PCAP_ERRBUF_SIZE];

    if (filename == NULL) {
        debug("ERROR: no pcap input\n");
        return -1;
    }

    //open file and create pcap handler
    handler = pcap_open_offline(filename, error_buf);

    if (handler == NULL) {
        debug("%s\n", error_buf);
        return -1;
    }

    if (pcap_datalink(handler) != DLT_EN10MB) {
        debug("this is not ethernet capture\n");
        pcap_close(handler);
        return -1;
    }

    // iterate pcap file
    uint32_t prev_ip1 = 0, prev_ip2 = 0;
    int ip_flag = 0;
    while (pcap_next_ex(handler, &header, &packet) >= 0) {
        // get ip
        ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
        ip_src = ip->ip_src.s_addr;
        ip_dst = ip->ip_dst.s_addr;

        if (ip_flag == 0) {
            prev_ip1 = ip_src;
            prev_ip2 = ip_dst;
            ip_flag = 1;
            continue;
        } 

        if ((ip_src != prev_ip1 && ip_src != prev_ip2) ||
            (ip_dst != prev_ip1 && ip_dst != prev_ip2)) {
            debug("there are more than two ip\n");
            return -1;
        }        
    }

    pcap_close(handler);
    return 0;
}

int check_application_count(char *filename) {
    struct sniff_ethernet *ethernet;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;
    struct sniff_udp *udp;
    struct sniff_openvpn openvpn;
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
    int application_layer_count;

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
    application_layer_count = 0;
    while (pcap_next_ex(handler, &header, &packet) >= 0) {
        // get ethernet
        ethernet = (struct sniff_ethernet *)(packet);

        // get ip
        ip = (struct sniff_ip *)(packet + SIZE_ETHERNET - ethernet_size);
        ip_size = IP_HL(ip)*4;

        if (ip_size < 20 || (ip_size > (ntohs(ip->ip_len)) && (ntohs(ip->ip_len) != 0))) {
            debug("invalid IP header length\n");
            continue;
        }

        // determine tcp or udp
        uint64_t temp_size;

        switch (ip->ip_p) {
        case IPPROTO_TCP:
            tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET - ethernet_size + ip_size);
            tcp_size = TH_OFF(tcp)*4;        
            temp_size = tcp_size;
            break;
        case IPPROTO_UDP:
            udp = (struct sniff_udp *)(packet + SIZE_ETHERNET - ethernet_size + ip_size);
            udp_size = ntohs(udp->uh_ulen);
            temp_size = 8;
            break;
        default:
            // debug("unknown protocol\n");
            continue;
        }

        // get payload size
        payload_size = ntohs(ip->ip_len) - (ip_size + temp_size);

        if (payload_size == 0) {
            // debug("payload size none\n");
            continue;
        }
        
        application_layer_count++;
    }

    pcap_close(handler);
    return application_layer_count;
}

int parse_pcap_into_packet_info(char *filename, struct packet_info *info_list, int nb_packet, int nb_byte) {
    struct sniff_ethernet *ethernet;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;
    struct sniff_udp *udp;
    char *payload;

    int ethernet_size;
    uint64_t ip_size;
    uint64_t tcp_size;
    uint64_t udp_size;
    uint64_t payload_size;
    uint64_t ip_src, ip_dst;
    uint64_t src_count, dst_count;

    const unsigned char *packet;  
    struct pcap_pkthdr *header;
    pcap_t *handler;

    char error_buf[PCAP_ERRBUF_SIZE];
    int application_layer_count;
    int packet_count;

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

    if (pcap_datalink(handler) == DLT_EN10MB) {
        ethernet_size = SIZE_ETHERNET;
    } else {
        ethernet_size = 0;
        debug("it is not an Ethernet capture\n");
    }

    // iterate pcap file
    application_layer_count = 0;
    src_count = dst_count = 0;
    packet_count = 0;
    while (pcap_next_ex(handler, &header, &packet) >= 0) {

        packet_count++;

        if (application_layer_count == nb_packet) {
            break;
        }

        // get ethernet
        ethernet = (struct sniff_ethernet *)(packet);

        if (header->caplen < ethernet_size + sizeof(struct sniff_ip)) {
            debug("packet is too short for IP header\n");
            continue;
        }

        // get ip
        ip = (struct sniff_ip *)(packet + ethernet_size);
        ip_size = IP_HL(ip)*4;

        if (ip_size < 20 || (ip_size > (ntohs(ip->ip_len)) && (ntohs(ip->ip_len) != 0))) {
            debug("invalid IP header length\n");
            continue;
        }

        // determine tcp or udp
        uint64_t temp_size;

        switch (ip->ip_p) {
        case IPPROTO_TCP:
            tcp = (struct sniff_tcp *)(packet + ethernet_size + ip_size);
            tcp_size = TH_OFF(tcp)*4;        
            temp_size = tcp_size;
            break;
        case IPPROTO_UDP:
            udp = (struct sniff_udp *)(packet + ethernet_size + ip_size);
            udp_size = ntohs(udp->uh_ulen);
            temp_size = 8;
            break;
        default:
            // debug("unknown protocol\n");
            continue;
        }

        if (application_layer_count == 0) {
            ip_src = ip->ip_src.s_addr;
            ip_dst = ip->ip_dst.s_addr;
        }

        // get payload
        payload = (char *)(packet + ethernet_size + ip_size + temp_size);
        payload_size = ntohs(ip->ip_len) - (ip_size + temp_size);

        if (payload_size == 0) {
            continue;
        }

        info_list[application_layer_count].openvpn.payload_length = payload_size - 2;
        info_list[application_layer_count].openvpn.openvpn_length = get_openvpn_length(payload, ip->ip_p);
        info_list[application_layer_count].openvpn.opcode = get_openvpn_opcode(payload, ip->ip_p);

        info_list[application_layer_count].wireguard.opcode = get_wireguard_opcode(payload, ip->ip_p);
        info_list[application_layer_count].ikev2.opcode = get_ikev2_opcode(payload, ip->ip_p);
        info_list[application_layer_count].ikev2.esp_marker = get_ikev2_marker(payload, ip->ip_p);
        
        info_list[application_layer_count].timestamp = header->ts;
        info_list[application_layer_count].transport_protocol = ip->ip_p;
        info_list[application_layer_count].payload_length = payload_size;

        info_list[application_layer_count].packet_count = packet_count;

        if (ip_src == ip->ip_src.s_addr) {
            info_list[application_layer_count].direction = SRC_TO_DST;
            src_count++;
        } else {
            info_list[application_layer_count].direction = DST_TO_SRC;
            dst_count++;
        }

        for (int i = 0; i < nb_byte; i++) {
            if (i >= payload_size) {
                info_list[application_layer_count].payload[i] = 0;
                continue;
            }
            info_list[application_layer_count].payload[i] = *((uint8_t *)(payload+i));
            // debug("%x ", *((uint8_t *)(payload+i)));
        }
        // debug("\n");
        
        application_layer_count++;
    }

    // if (src_count < PACKET_WINDOW_SIZE && dst_count < PACKET_WINDOW_SIZE) {
    //     debug("The number of packets in single direction should be more than %d (src : %ld, dst : %ld)\n", PACKET_WINDOW_SIZE, src_count, dst_count);
    //     return -1;
    // }

    if (src_count > dst_count) {
        info_list[0].total_direction = SRC_TO_DST;
    } else {
        info_list[0].total_direction = DST_TO_SRC;
    }

    pcap_close(handler);
    return 0;
}