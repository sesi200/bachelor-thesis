#ifndef DATATRANSPORT_H_
#define DATATRANSPORT_H_

#include "net/ip/uip.h"
#include "simple-udp.h"
#include "stiki-main.h"
#include "stiki-crypto.h"
#include "alert.h"

//numbers used to identify what is in the packet
#define MSG_TYPE_DATA_TRANSPORT_IV 0x01
#define MSG_TYPE_DATA_TRANSPORT_CTR 0x02

//ATTENTION: This is not the method to use as a user of sTiki. In that case, use stiki_udp_sendto(...) in stiki.h
//encrypts and sends the data
//assumes that a session already exists
int datatransport_sendto(struct simple_udp_connection *c, const void *data, uint16_t datalen, const uip_ipaddr_t *to);

//processes a datatransport packet
//the decrypted payload will be forwarded to the method set with set_stiki_packet_handler(...)
void handle_data_transport(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen);

#endif /*DATATRANSPORT_H_*/
