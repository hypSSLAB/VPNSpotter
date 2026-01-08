#ifndef PACKET_H
#define PACKET_H

#include "core.h"
#include "debug.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];   /* destination host address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];   /* source host address */
    uint16_t ether_type;                    /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    uint8_t  ip_vhl;                /* version << 4 | header length >> 2 */
    uint8_t  ip_tos;                /* type of service */
    uint16_t ip_len;                /* total length */
    uint16_t ip_id;                 /* identification */
    uint16_t ip_off;                /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    uint8_t  ip_ttl;                /* time to live */
    uint8_t  ip_p;                  /* protocol */
    uint16_t ip_sum;                /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef uint32_t tcp_seq;

struct sniff_tcp {
    uint16_t th_sport;              /* source port */
    uint16_t th_dport;              /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    uint8_t  th_offx2;              /* data offset, rsvd */
    #define TH_OFF(th)          (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS            (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t th_win;                /* window */
    uint16_t th_sum;                /* checksum */
    uint16_t th_urp;                /* urgent pointer */
};

/* UDP header. */
struct sniff_udp {
    uint16_t uh_sport;              /* source port */
    uint16_t uh_dport;              /* destination port */
    uint16_t uh_ulen;               /* udp length */
    uint16_t uh_sum;                /* udp checksum */
};
#define OPENVPN_OPCODE_MAX  32      /* 2^5 */
#define P_OPCODE_SHIFT      3  
#define SNIFF_OPENVPN_MAX   100
#define SRC_TO_DST          0
#define DST_TO_SRC          1

/* OpenVPN header */
struct sniff_openvpn {
    uint16_t payload_length;
    uint16_t openvpn_length;
    uint8_t opcode;
    uint8_t transport_protocol;
    uint8_t direction;
};

/* wireguard struct */
struct sniff_wireguard {
    uint8_t opcode;
};

/* ikev2/ipsec struct */
struct sniff_ikev2 {
    uint32_t esp_marker;
    uint8_t opcode; 
};

#define PACKET_NOT_USED     0
#define PACKET_USED         1

#define NB_FILTER_MAX       3

/* packet info */
struct packet_info {
    struct sniff_openvpn openvpn;
    struct sniff_wireguard wireguard;
    struct sniff_ikev2 ikev2;

    struct timeval timestamp;
    uint16_t payload_length;
    uint8_t transport_protocol;
    uint8_t direction;
    
    uint8_t total_direction;
    uint8_t filter_applied;

    uint64_t packet_count;
    uint8_t *payload;

    uint8_t filter_by_latency;
    uint8_t filter_by_zero;
    uint8_t filter_by_length;

    uint8_t packet_segmented;
    uint8_t nb_filter_passed;
    uint8_t nb_filter_applied;
};

int check_ip_address(char *filename);
int check_application_count(char *filename);
int parse_pcap_into_packet_info(char *filename, struct packet_info *info_list, int nb_packet, int nb_byte);

uint8_t get_openvpn_opcode(char *payload, int protocol);
uint16_t get_openvpn_length(char *payload, int protocol);
const char *opcode_to_string(uint8_t opcode);
uint8_t get_wireguard_opcode(const char *payload, uint8_t ip_proto);
uint8_t get_ikev2_opcode(const char *payload, uint8_t ip_proto);
uint32_t get_ikev2_marker(const char *payload, uint8_t ip_proto);

#endif // PACKET_H