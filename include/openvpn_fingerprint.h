#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include "core.h"
#include "debug.h"

// since tcp openvpn payloads are fragmented into multiple tcp packets, not all lengths can match
// 0 <= LENGTH_MATCH_RATIO <= 100
#define LENGTH_MATCH_RATIO              30

// since tcp openvpn payloads are fragmented into multiple tcp packets, opcode we identyfing may not be opcode
// 0 <= OPCODE_SET_RATIO <= 100
#define OPCODE_SET_RATIO                20

#define OPCODE_SET_MIN                  4
#define OPCODE_SET_MAX                  10

#define ACK_FINGERPRINT_BIN_SIZE        10
#define ACK_FINGERPRINT_WINDOW_SIZE     SNIFF_OPENVPN_MAX/ACK_FINGERPRINT_BIN_SIZE

#define DATA_FINGERPRINT_BIN_SIZE        10
#define DATA_FINGERPRINT_WINDOW_SIZE     SNIFF_OPENVPN_MAX/DATA_FINGERPRINT_BIN_SIZE

int opcode_fingerprint_old(struct sniff_openvpn openvpn_arr[]);
int ack_fingerprint_old(struct sniff_openvpn openvpn_arr[]);

int parse_pcap_into_openvpn(char *filename, struct sniff_openvpn openvpn_arr[]);

typedef int (*func_fingerprint)(struct sniff_openvpn[]);
extern func_fingerprint funcs[];
extern char *funcs_str[];

#endif // FINGERPRINT_H