#include "stiki.h"

void set_stiki_packet_handler(packet_handler ph) {
    set_stiki_packet_handler_main(ph);
}

void init_stiki() {
    init_stiki_main();
}

int stiki_udp_sendto(struct simple_udp_connection *c,
                    const void *data, uint16_t datalen,
                    const uip_ipaddr_t *to) {
    return stiki_udp_sendto_main(c, data, datalen, to);
}

void stiki_receive(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen) {
    stiki_receive_main(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
}