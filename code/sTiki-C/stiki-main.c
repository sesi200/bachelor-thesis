#include "stiki-main.h"

void set_stiki_packet_handler_main(packet_handler ph) {data_processor = ph;}

void init_stiki_main() {
    on_boot_handshake_init();
}

void set_header(stiki_hdr *hdr, uint8_t protocol, uint8_t subprotocol) {
    memset(hdr, 0, sizeof(stiki_hdr));
    hdr->magic = STIKI_MAGIC; //same for all STIKI packets
    //type-byte: 3 bits to determine protocol (data_transport, handshake or alert), followed by 5 bits for the sub-protocol (e.g. M1, M2, M3 or M4 for the handshake protocol)
    hdr->type = (( (protocol & 0x7)<<5) | (subprotocol & 0x1f));
}

uint8_t read_protocol(const uint8_t *data) {
    //the first three bits of the second byte denote the protocol
    return (data[1] & (0x7<<5)) >> 5;
}

uint8_t read_subprotocol(const uint8_t *data) {
    //bits 4-8 in the second byte denote the subprotocol
    return data[1] & 0x1f;
}

void set_iv_message_counter(stiki_iv *iv, uint16_t counter) {
    //counter is 2 bytes long, set 3rd and 2nd last bytes of IV
    iv->bytes[IV_LENGTH-3] = (uint8_t) (counter >> 8);
    iv->bytes[IV_LENGTH-2] = (uint8_t) (counter & 0xff);
}

uint16_t get_iv_message_counter(stiki_iv *iv) {
    uint16_t counter;
    //counter is in 3rd and 2nd last bytes
    counter = iv->bytes[IV_LENGTH-3] << 8;
    counter |= iv->bytes[IV_LENGTH-2] & 0xff;
    return counter;
}

void inc_iv_message_counter(stiki_iv *iv) {
    uint16_t counter;
    counter = get_iv_message_counter(iv);
    counter++;
    set_iv_message_counter(iv, counter);
}

void set_iv_block_counter(stiki_iv *iv, uint8_t counter) {
    //the last byte of the iv is the block counter
    iv->bytes[IV_LENGTH-1] = counter;
}

void inc_iv_block_counter(stiki_iv *iv) {
    //the last byte of the iv is the block counter
    ++(iv->bytes[IV_LENGTH-1]);
}

int stiki_udp_sendto_main(struct simple_udp_connection *c,
                    const void *data, uint16_t datalen,
                    const uip_ipaddr_t *to) {

    if (!is_session_available(id_from_ip(to))) {
        //begin handshake
        return initiate_handshake(c, to, data, datalen);
    }

    return datatransport_sendto(c, data, datalen, to);
}

int is_stiki_packet(const uint8_t *data) {
    return data[0] == STIKI_MAGIC;
}

void stiki_receive_main(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen) {

        if(!is_stiki_packet(data)) {
            //handle data received
            (*data_processor)(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
        }

        uint8_t protocol = read_protocol(data);
        //dispatch message to correct protocol handler
        switch(protocol) {
            case PROTOCOL_DATA_TRANSPORT:
                handle_data_transport(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
                break;
            case PROTOCOL_HANDSHAKE:
                handle_handshake(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
                break;
            case PROTOCOL_ALERT:
                handle_alert(c, sender_addr, sender_port, receiver_addr, receiver_port, data, datalen);
                break;
            default:
                ;
                //no correct protocol found
        }
}

uint16_t id_from_ip(const uip_ipaddr_t *addr) {
    return uip_htons(addr->u16[7]);
}