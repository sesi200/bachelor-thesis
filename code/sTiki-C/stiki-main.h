#ifndef STIKI_H_
#define STIKI_H_

#include "net/ip/uip.h" //defines uip_ipaddr_t
#include "sys/clock.h"
#include "simple-udp.h"
#include <string.h> //import memcpy
#include <stdlib.h> //import malloc

//turning this option on makes the node occasionally forget the current session or the IV associated with it. Probability: ~7% on each message received
#ifndef SIMULATE_UNRELIABLE_NODE
#define SIMULATE_UNRELIABLE_NODE 0
#endif

#ifndef HANDSHAKE_TIMEOUT
#define HANDSHAKE_TIMEOUT 9 //in seconds
#endif
#ifndef SESSION_TIMEOUT
#define SESSION_TIMEOUT 3600 //in seconds
#endif

#ifndef STIKI_MAX_SESSION_COUNT
#define STIKI_MAX_SESSION_COUNT 3
#endif

#include "lib/aes-128.h"
// the block-size for AES is 128bits=16bytes
#define BLOCK_SIZE AES_128_BLOCK_SIZE
#define MAC_LENGTH BLOCK_SIZE
#define KEY_LENGTH BLOCK_SIZE
#define IV_LENGTH BLOCK_SIZE
#define IV_TRANSPORT_LENGTH (IV_LENGTH - 3)
#define NONCE_LENGTH 4

//this is the magic number prepended to every packet which belongs to sTiki
#define STIKI_MAGIC 0xef

//numbers used to identify the protocol the message belongs to
#define PROTOCOL_DATA_TRANSPORT 0x01
#define PROTOCOL_HANDSHAKE 0x02
#define PROTOCOL_ALERT 0x03


//this defines packet_handler as a function pointer that takes the necessary things to process a packet
typedef void (*packet_handler)(
        struct simple_udp_connection*,
        const uip_ipaddr_t*, //sender address
        uint16_t, //sender port
        const uip_ipaddr_t*, //receiver address
        uint16_t, //receiver port
        const uint8_t*, //data
        uint16_t); //datalen

typedef struct {
    uint8_t magic;
    uint8_t type; //3 bits protocol, 5 bits subprotocol
} stiki_hdr;

typedef struct {
    uint8_t is_set;
    //iv: [IV_TRANSPORT_LENGTH bytes random IV, 2 bytes message counter, 1 byte block counter]
    uint8_t bytes[IV_LENGTH];
} stiki_iv;

typedef struct {
    uint8_t bytes[NONCE_LENGTH];
} stiki_nonce;

//those includes rely upon all the defined structs
//that's the reason why they're included so late into the file
#include "stiki-crypto.h"
#include "datatransport.h"
#include "handshake.h"
#include "alert.h"
#include "sessionstore.h"

//stores the function to be called once a data packet has been extracted (set with set_stiki_packet_handler(...))
packet_handler data_processor;
//function to be called on system boot to register the correct data_processor
void set_stiki_packet_handler_main(packet_handler ph);
//function to be called on system boot to set up everything for sTiki
void init_stiki_main();
//encrypts and sends a message
//if necessary, first does the handshake
int stiki_udp_sendto_main(struct simple_udp_connection *c,
                    const void *data, uint16_t datalen,
                    const uip_ipaddr_t *to);
//Feed freshly received messages in here.
//This method handles any sTiki-related actions to take and then (if the message contains any data) pass the data through to the application's message receiver
//If the packet is not a sTiki-packet, it will pass it along unmodified to the application's message receiver
void stiki_receive_main(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen);

//sets the header's bytes correctly
void set_header(stiki_hdr *hdr, uint8_t protocol, uint8_t subprotocol);
int is_stiki_packet(const uint8_t *data);
//input: pointer to beginning of packet
//return: which protocol the packet belongs to (eg. PROTOCOL_ALERT)
uint8_t read_protocol(const uint8_t *data);
//input: pointer to beginning of packet
//return: which subprotocol the packet belongs to
uint8_t read_subprotocol(const uint8_t *data);

//iv manipulation
void set_iv_message_counter(stiki_iv *iv, uint16_t counter);
uint16_t get_iv_message_counter(stiki_iv *iv);
void inc_iv_message_counter(stiki_iv *iv);
void set_iv_block_counter(stiki_iv *iv, uint8_t counter);
void inc_iv_block_counter(stiki_iv *iv);

//extracts a node ID from its ip address
uint16_t id_from_ip(const uip_ipaddr_t *addr);

#endif /*STIKI_H_*/
