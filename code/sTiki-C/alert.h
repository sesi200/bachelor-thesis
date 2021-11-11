#ifndef ALERT_H_
#define ALERT_H_

#include "net/ip/uip.h"
#include "simple-udp.h"
#include "stiki-crypto.h"

//numbers to identify the type of alert
#define MSG_TYPE_ALERT_INVALID_SESSION_TO_KEYSERVER 0x04
#define MSG_TYPE_ALERT_INVALID_SESSION_TO_NODE 0x05
#define MSG_TYPE_ALERT_NO_IV 0x03

//processes an alert packet.
void handle_alert(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen);

#endif /*ALERT_H_*/
