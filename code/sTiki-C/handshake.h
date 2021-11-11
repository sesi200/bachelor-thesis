#ifndef HANDSHAKE_H_
#define HANDSHAKE_H_

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/clock.h"
#include "simple-udp.h"
#include "stiki-main.h"
#include "stiki-crypto.h"

//The handshake consists of messages M1 through M4.
//These numbers identify which message is which.
#define MSG_TYPE_HANDSHAKE_M1 0x01
#define MSG_TYPE_HANDSHAKE_M2 0x02
#define MSG_TYPE_HANDSHAKE_M3 0x03
#define MSG_TYPE_HANDSHAKE_M4 0x04

//constants to track the handshake progress
#define STIKI_HS_STATE_IDLE 0x01
#define STIKI_HS_STATE_M1_SENT 0x02
#define STIKI_HS_STATE_M2_SENT 0x03
#define STIKI_HS_STATE_M4_SENT 0x04

#define STIKI_HS_ROLE_INIT 0x01
#define STIKI_HS_ROLE_REC 0x02

typedef struct {
    uint8_t state;
    uint16_t target_id;
    struct simple_udp_connection *partner_conn;
    uip_ipaddr_t target_ip;
    stiki_nonce my_nonce;
    uint8_t my_token[24];
    unsigned long timestamp;
    uint8_t *stored_msg;
    uint16_t stored_msg_len;
} stiki_handshake_context;

uip_ipaddr_t keyserver_addr;
struct simple_udp_connection keyserver_conn;

//this method is called on system boot
void on_boot_handshake_init();

//starts a new handshake
//it will store the message until the handshake is complete an then send the message
int initiate_handshake(struct simple_udp_connection *conn, const uip_ipaddr_t *target_ip, const uint8_t *msg, uint16_t msglen);

//handles a handshake packet
void handle_handshake(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen);

#endif /*HANDSHAKE_H_*/
