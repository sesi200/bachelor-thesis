#include "datatransport.h"

//sends an alert packet to target node to signal a missing IV
//assumption: the session between the nodes is already established
void report_missing_iv(struct simple_udp_connection *conn, const uip_ipaddr_t *to) {
    //packet to construct: [header: 2b, local_id: 2b, remote_id: 2b, MAC: 16b]
    //total packet size: 22
    uint8_t msg[22];
    stiki_hdr hdr;
    uint16_t remote_id = id_from_ip(to);
    //header
    set_header(&hdr, PROTOCOL_ALERT, MSG_TYPE_ALERT_NO_IV);
    memcpy(msg, &hdr, 2);
    //remote_id
    msg[2] = remote_id >> 8;
    msg[3] = remote_id & 0xff;
    //local_id
    msg[4] = NODEID >> 8;
    msg[5] = NODEID & 0xff;

    compute_mac(&msg[6], msg, 6, sessions[search_session_idx(remote_id)]->mac_key); //we know the session exists because otherwise report_missing_session would have been called

    simple_udp_sendto(conn, msg, 22, to);
}

//sends an alert packet to target node to signal a missing session
//to do this, we notify the key server of the missing session. If our notification is valid (and we are allowed to talk to the other node), the key server will notify the other node.
//The other node will initiate a new handshake
void report_missing_session(uint16_t remote_id) {
    //packet to construct: [header: 2b, local_id: 2b, remote_id: 2b, MAC: 16b]
    //total packet size: 22
    uint8_t msg[22];
    uint8_t imk[] = INITIAL_MASTER_KEY;

    //header
    stiki_hdr hdr;
    set_header(&hdr, PROTOCOL_ALERT, MSG_TYPE_ALERT_INVALID_SESSION_TO_KEYSERVER);
    memcpy(msg, &hdr, 2);

    //origin id (the node that tried to send something to us)
    msg[2] = remote_id>>8;
    msg[3] = remote_id&0xff;

    //target(this node) id
    msg[4] = NODEID>>8;
    msg[5] = NODEID&0xff;

    compute_mac(&msg[6], msg, 6, imk);
    simple_udp_send(&keyserver_conn, msg, 22);
}

//helper method for datatransport_sendto(...).
//Calculates the total packet size.
uint16_t msg_len(uint16_t payload_len, uint8_t send_iv_along) {
    if (send_iv_along)
        return payload_len+15+MAC_LENGTH; //header(2b) + IV(13b)
    else
        return payload_len+4+MAC_LENGTH; //header(2b) + msg_counter(2b)
}

//method description in .h file
int datatransport_sendto(struct simple_udp_connection *c, const void *data, uint16_t datalen, const uip_ipaddr_t *to) {

    int ret;
    uint16_t position = 0;
    uint8_t send_iv_along;
    const uint8_t *mac_key;
    const uint8_t *payload_key;
    stiki_session *session;
    stiki_iv *iv;
    uint8_t* msg;
    uint8_t session_id = search_session_idx(id_from_ip(to));
    session = sessions[session_id];

    //read session keys
    mac_key = session->mac_key;
    payload_key = session->crypt_key;

    //get/generate iv
    iv = &session->my_iv;
    if ((send_iv_along = (!iv->is_set))) {
        generate_iv(iv);
        set_iv_message_counter(iv, 0);
    } else {
        inc_iv_message_counter(iv);
    }

    msg = malloc((msg_len(datalen, send_iv_along))*sizeof(uint8_t));

    //build header
    stiki_hdr hdr;
    if (send_iv_along) {
        set_header(&hdr, PROTOCOL_DATA_TRANSPORT, MSG_TYPE_DATA_TRANSPORT_IV);
    } else {
        set_header(&hdr, PROTOCOL_DATA_TRANSPORT, MSG_TYPE_DATA_TRANSPORT_CTR);
    }
    msg[0]=hdr.magic;
    msg[1]=hdr.type;
    position += 2;

    //add msg_counter or IV
    if (send_iv_along) {
        //send along IV (13 bytes)
        memcpy(&msg[position], iv->bytes, 13);
        position += 13;
    } else {
        //send along msg_counter(2 bytes)
        memcpy(&msg[position], &iv->bytes[13], 2);
        position += 2;
    }

    //add encrypted payload to our packet
    memcpy(&msg[position], data, datalen);
    encrypt_message(&msg[position], datalen, iv, payload_key);
    position += datalen;

    //MAC computation, send message
    compute_mac(&msg[position], msg, position, mac_key);
    ret = simple_udp_sendto(c, msg, position+MAC_LENGTH, to);

    //cleanup
    free(msg);
    return ret;
}

//method description in .h file
void handle_data_transport(struct simple_udp_connection *conn,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen) {

    uint16_t data_start;
    uint16_t payload_len;
    uint16_t sender_id = id_from_ip(sender_addr);

    if (!is_session_available(sender_id)) {
        report_missing_session(sender_id);
        return;
    }
    //simulate unreliable network
    if (SIMULATE_UNRELIABLE_NODE && (clock_seconds()%19 == 0)) {
        report_missing_session(sender_id);
        return;
    }
    stiki_session *session = sessions[search_session_idx(sender_id)];

    //check MAC
    if (!mac_is_valid(data+datalen-MAC_LENGTH, data, datalen-MAC_LENGTH, session->mac_key)) {
        return;
    }

    if(read_subprotocol(data)==MSG_TYPE_DATA_TRANSPORT_IV) {
        //first IV_TRANSPORT_LENGTH bytes after header indicate the new IV
        data_start = 2+IV_TRANSPORT_LENGTH;
        memcpy(session->remote_iv.bytes, &data[2], IV_TRANSPORT_LENGTH);
        session->remote_iv.is_set = 1;
        set_iv_message_counter(&session->remote_iv, 0); //the first message with a new IV is always message 0

    } else { /*MSG_TYPE_DATA_TRANSPORT_CTR*/

        if (!session->remote_iv.is_set) {
            report_missing_iv(conn, sender_addr);
            return;
        }
        //simulate unreliable network
        if ((clock_seconds()%17==0) && SIMULATE_UNRELIABLE_NODE) {
            report_missing_iv(conn, sender_addr);
            return;
        }

        //first two bytes after header indicate the message counter
        uint16_t msg_counter = (data[2]<<8) | data[3];
        set_iv_message_counter(&session->remote_iv, msg_counter);
        data_start = 4; //header: 2, msg_counter: 2
    }
    payload_len = datalen - data_start - MAC_LENGTH;

    //decrypt message
    uint8_t payload[payload_len];
    memcpy(payload, &data[data_start], payload_len);
    encrypt_message(payload, payload_len, &session->remote_iv, session->crypt_key); //in counter mode, encryption is the same as decryption

    //propagate payload to next protocol
    data_processor(conn, sender_addr, sender_port, receiver_addr, receiver_port, payload, payload_len);
}