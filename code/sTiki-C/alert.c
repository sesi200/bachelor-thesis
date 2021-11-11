#include "alert.h"

void handle_no_iv(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen) {

    //expected: [2b header, 2b my ID, 2b target ID, 16b MAC]

    if (datalen != 22) return;

    if (is_session_available(id_from_ip(sender_addr))) {
        stiki_session *session = sessions[search_session_idx(id_from_ip(sender_addr))];
        if (mac_is_valid(&data[6], data, 6, session->mac_key)) {
            //we cannot resend the packet because messages are not stored
            session->my_iv.is_set = 0;
        }
    }
}

void handle_no_session(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen) {

    //expected: [2b header, 2b my ID, 2b target ID, 16b MAC]

    if (datalen != 22) return;

    uint8_t imk[] = INITIAL_MASTER_KEY;

    if (!mac_is_valid(&data[6], data, 6, imk)) {
        return;
    }

    uint16_t my_id = (data[2]<<8) | data[3];
    uint16_t target_id = (data[4]<<8) | data[5];

    if (my_id != NODEID) return;

    invalidate_session(target_id);
}

//reads the subprotocol and dispatches to handle_no_iv(...) or handle_no_session(...)
void handle_alert(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen) {
    switch (read_subprotocol(data)) {
        case MSG_TYPE_ALERT_NO_IV:
            handle_no_iv(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
            break;
        case MSG_TYPE_ALERT_INVALID_SESSION_TO_NODE:
            handle_no_session(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
            break;
        default:
            //MSG_TYPE_ALERT_INVALID_SESSION_TO_KEYSERVER is not handled because it is meant for the keyserver
            return;
    }
}