#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"

const char *opcode_str[] = {
    "NONE",
    "P_CONTROL_HARD_RESET_CLIENT_V1",
    "P_CONTROL_HARD_RESET_SERVER_V1",
    "P_CONTROL_SOFT_RESET_V1",
    "P_CONTROL_V1",
    "P_ACK_V1",
    "P_DATA_V1",
    "P_CONTROL_HARD_RESET_CLIENT_V2",
    "P_CONTROL_HARD_RESET_SERVER_V2",
    "P_DATA_V2",
};

uint8_t get_openvpn_opcode(char *payload, int protocol) {
    uint8_t opcode;

    if (protocol == IPPROTO_TCP) opcode = *(payload+2);
    else if (protocol == IPPROTO_UDP) opcode = *(payload);
    else return -1;

    opcode = opcode >> P_OPCODE_SHIFT;

    return opcode;    
}

uint16_t get_openvpn_length(char *payload, int protocol) {
    uint16_t length;

    if (protocol != IPPROTO_TCP) return 0;

    length = (*payload) * 0x100 + *(payload+1);

    return length;
}

const char *opcode_to_string(uint8_t opcode) {
    uint64_t length = sizeof(opcode_str)/sizeof(opcode_str[0]);
    if (opcode >= length) {      
        return NULL;
    }
    return opcode_str[opcode];
}

uint8_t get_wireguard_opcode(const char *payload, uint8_t ip_proto) {
    if (ip_proto != IPPROTO_UDP) {
        return 0; 
    }
    if (payload == NULL) {
        return 0;
    }

    uint32_t raw = 0;
    raw = *((uint32_t*)payload); 
    uint8_t msg_type = (uint8_t)(raw & 0xFF);

    return msg_type; 
}

uint8_t get_ikev2_opcode(const char *payload, uint8_t ip_proto) {
    if (ip_proto != IPPROTO_UDP || payload == NULL) {
        return 0;
    }

    // offset=0..7   = Initiator SPI
    // offset=8..15  = Responder SPI
    // offset=16     = Next Payload
    // offset=17     = Version
    // offset=18     = Exchange Type
    // offset=19     = Flags
    // ...
    // => exchange type = payload[18]
    return (uint8_t)payload[18];
}

uint32_t get_ikev2_marker(const char *payload, uint8_t ip_proto) {
    if (ip_proto != IPPROTO_UDP || payload == NULL) {
        return 0;
    }
    return *((uint32_t *)payload);
}