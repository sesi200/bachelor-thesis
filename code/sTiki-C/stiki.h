//this is just a facade to filter out all the
//methods you really need to know about how to use sTiki.
//recommended options to pass to the compiler:
//HANDSHAKE_TIMEOUT (in seconds), default: 9. Defines when a handshake counts a s timed out. Don't make this too long because the nodes only handle one handshake at a time.
//SESSION_TIMEOUT (in seconds), default: 3600. Defines how long a session has to be unused for the session to count as timed out. Don't put this smaller than 2x the minimum sending interval (messages get dropped sometimes), it will force a lot of unneccessary handshakes.
//STIKI_MAX_SESSION_COUNT, default: 3. Defines the maximum number of simultaeous sessions to keep in RAM. (when using TinyIPFIX for aggregators: recommended number is at least degree of aggregation +1, collectors should be fine when using 1 or (once pulling functionality is implemented) 2)
//INITIAL_MASTER_KEY, default: {0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77}. Contains the node's masterkey, which also has to be registered in Comada in conf/keystore.properties

#include "stiki-main.h"

//function to be called on system boot to register the correct function to receive decrypted payloads
//packet_handler has the same signature as stiki_receive(...), (see below)
//packet_handler is defined in stiki-main.h
void set_stiki_packet_handler(packet_handler ph);

//function to be called on system boot to set up everything for sTiki
void init_stiki();

//Encrypts and sends a message to a specific node.
//If necessary, it first does the handshake.
//This probably will be your most-used function.
//sTiki does not support broadcasts. However, you can broadcast without using sTiki (use simple_udp for that).
int stiki_udp_sendto(struct simple_udp_connection *c,
                    const void *data, uint16_t datalen,
                    const uip_ipaddr_t *to);

//Feed freshly received messages in here.
//This method handles any sTiki-related actions to take and then (if the message contains any data) passes the data through to the application's message receiver
//If the packet is not a sTiki-packet, it will pass it along unmodified to the application's message receiver
void stiki_receive(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen);