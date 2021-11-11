#include "handshake.h"

//we only handle one handshake at a time. This context is to track it
static stiki_handshake_context context;

void reset_handshake_context() {
    free(context.stored_msg);
    memset(&context, 0, sizeof(stiki_handshake_context));
    context.state = STIKI_HS_STATE_IDLE;
}

//method description in .h file
void on_boot_handshake_init() {
    reset_handshake_context();

    //set up keyserver/any_node connection
    uip_ip6addr(&keyserver_addr,UIP_DS6_DEFAULT_PREFIX,0,0,0,0,0,0,1);
    simple_udp_register(&keyserver_conn, 0, &keyserver_addr, 1234, stiki_receive_main);
}

uint8_t handshake_in_progress() {
    if (context.state==STIKI_HS_STATE_IDLE) {
        //no handshake saved as in progress
        return 0;
    }
    if ((context.timestamp+HANDSHAKE_TIMEOUT) < clock_seconds()) {
        //last handshake timed out
        return 0;
    }
    return 1;
}

//method description in .h file
int initiate_handshake(struct simple_udp_connection *conn, const uip_ipaddr_t *target_ip, const uint8_t *msg, uint16_t msglen) {

    if (handshake_in_progress()) {
        //only 1 handshake is running at the same time
        return 1;
    } else {
        reset_handshake_context();
    }

    //setup context
    context.target_id = id_from_ip(target_ip);
    generate_nonce(&context.my_nonce);
    context.timestamp = clock_seconds();
    context.state = STIKI_HS_STATE_M1_SENT;
    context.stored_msg_len = msglen;
    context.stored_msg = malloc(msglen * sizeof(uint8_t));
    memcpy(context.stored_msg, msg, msglen);

    //build/send M1
    //M1: [2b header, 2b local ID, 2b remote ID, 4b local nonce]
    //total: 10 bytes

    //header
    stiki_hdr hdr;
    set_header(&hdr, PROTOCOL_HANDSHAKE, MSG_TYPE_HANDSHAKE_M1);
    uint8_t message[10];
    memcpy(message, &hdr, 2);
    //local ID
    message[2] = NODEID >> 8;
    message[3] = NODEID & 0xff;
    //remote ID
    message[4] = context.target_id>>8;
    message[5] = context.target_id & 0xff;
    //nonce
    memcpy(message+6, context.my_nonce.bytes, NONCE_LENGTH);

    //according to sTiki spec, we return success when M1 successfully has been sent
    return simple_udp_sendto(conn, message, 10, target_ip);
}

void handle_m1(struct simple_udp_connection *c,
    const uip_ipaddr_t *sender_addr,
    uint16_t sender_port,
    const uip_ipaddr_t *receiver_addr,
    uint16_t receiver_port,
    const uint8_t *data,
    uint16_t datalen) {

    //expected M1: [header(2b), id_a(2b), id_b(2b), nonce_a(4b)]
    //total: 10 bytes
    if (datalen != 10) {
        return;
    }

    if (((data[4]<<8) | data[5]) != NODEID) {
        //message not meant for this node
        return;
    }

    if (handshake_in_progress()) {
        //we can have only 1 handshake at the same time
        return;
    } else {
        reset_handshake_context();
    }

    context.target_id = (data[2]<<8) | data[3];
    context.timestamp = clock_seconds();
    context.state = STIKI_HS_STATE_M2_SENT;
    context.partner_conn = c;
    uip_ipaddr_copy(&context.target_ip, sender_addr);
    generate_nonce(&context.my_nonce);

    //build M2
    //M2: [header(2b), id_a(2b), id_b(2b), nonce_a(4b), nonce_b(4b)]
    //total: 14 bytes
    uint8_t m2[14];
    stiki_hdr hdr;
    set_header(&hdr, PROTOCOL_HANDSHAKE, MSG_TYPE_HANDSHAKE_M2);
    memcpy(m2, &hdr, 2);
    memcpy(&m2[2], &data[2], 8);
    memcpy(&m2[10], context.my_nonce.bytes, NONCE_LENGTH);

    simple_udp_send(&keyserver_conn, m2, 14);
}

void handle_m3(struct simple_udp_connection *c,
    const uip_ipaddr_t *sender_addr,
    uint16_t sender_port,
    const uip_ipaddr_t *receiver_addr,
    uint16_t receiver_port,
    const uint8_t *data,
    uint16_t datalen) {
//expected: [header(2b), iv(15b), token_a(24b), mac_a(16b), token_b(24b), mac_b(16b)]
//therefore header starts at 0
//          iv starts at 2
//          token_a starts at 17
//          mac_a stats at 41
//          token_b starts at 57
//          mac_b starts at 81
    if (datalen != 97) return;
    if (!handshake_in_progress()) return;

    uint8_t imk[BLOCK_SIZE] = INITIAL_MASTER_KEY;

    if (!mac_is_valid(&data[81], data, 81, imk)) {
        return;
    }

    //read data
    stiki_iv iv;
    memcpy(iv.bytes, &data[2], 15);

    //handle my token
    memcpy(context.my_token, &data[57], 24);
    encrypt_message(context.my_token, 24, &iv, imk); //decrypt token_b
    uint16_t id_a = (context.my_token[0]<<8) | context.my_token[1];
    uint16_t id_b = (context.my_token[2]<<8) | context.my_token[3];
    if (id_b != NODEID) return;
    if (id_a != context.target_id) return;
    if (memcmp(context.my_nonce.bytes, &context.my_token[4], NONCE_LENGTH)) return;

    //message is valid, set session key
    stiki_session *session = sessions[create_session(context.target_id)];
    set_session_key(session, &context.my_token[8]);

    //forward data to node_a
    uint8_t m4[57];//message to send along to node_a
    memcpy(m4, data, 57);
    //fix header
    stiki_hdr hdr;
    set_header(&hdr, PROTOCOL_HANDSHAKE, MSG_TYPE_HANDSHAKE_M4);
    m4[1] = hdr.type;

    simple_udp_sendto(context.partner_conn, m4, 57, &context.target_ip);

    reset_handshake_context();
}

void handle_m4(struct simple_udp_connection *c,
    const uip_ipaddr_t *sender_addr,
    uint16_t sender_port,
    const uip_ipaddr_t *receiver_addr,
    uint16_t receiver_port,
    const uint8_t *data,
    uint16_t datalen) {
//expected: [header(2b), iv(15b), token_a(24b), mac_a(16b)]
    if (datalen != 57) return;
    if (!handshake_in_progress()) return;
    if (id_from_ip(sender_addr) != context.target_id) return;

    uint8_t imk[BLOCK_SIZE] = INITIAL_MASTER_KEY;
    if (!mac_is_valid(data+41, data, 41, imk)) {
        return;
    }

    //read data
    stiki_iv iv;
    memcpy(iv.bytes, data+2, 15);
    memcpy(context.my_token, data+17, 24);
    encrypt_message(context.my_token, 24, &iv, imk);
    uint16_t id_a = (context.my_token[0]<<8)|context.my_token[1];
    uint16_t id_b = (context.my_token[2]<<8)|context.my_token[3];
    if ((id_a!=NODEID) || (id_b!=context.target_id)) {
        return;
    }

    if (memcmp(context.my_token+4, context.my_nonce.bytes, NONCE_LENGTH)) {
        return; //nonce does not match
    }

    //create new session
    stiki_session *session = sessions[create_session(context.target_id)];
    set_session_key(session, &context.my_token[8]);

    //finally send the stored message now that it can be sent securely
    stiki_udp_sendto_main(c, context.stored_msg, context.stored_msg_len, sender_addr);

    reset_handshake_context();
}

//dispatches the message to the right handler
void handle_handshake(struct simple_udp_connection *c,
    const uip_ipaddr_t *sender_addr,
    uint16_t sender_port,
    const uip_ipaddr_t *receiver_addr,
    uint16_t receiver_port,
    const uint8_t *data,
    uint16_t datalen) {

    //determine how to handle the packet
    uint8_t subprotocol = read_subprotocol(data);
    switch (subprotocol) {
        case MSG_TYPE_HANDSHAKE_M1:
            handle_m1(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
            break;
        case MSG_TYPE_HANDSHAKE_M2:
            //we can't handle M2. M2 is supposed to arrive at the key server.
            return;
        case MSG_TYPE_HANDSHAKE_M3:
            handle_m3(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
            break;
        case MSG_TYPE_HANDSHAKE_M4:
            handle_m4(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
            break;
        default:
            //should not happen
            return;
    }
}