#ifndef SESSIONSTORE_H_
#define SESSIONSTORE_H_

#include "stiki-main.h"

#include "lib/memb.h"
#include "sys/clock.h"

typedef struct {
    uint16_t node_id;
    stiki_iv my_iv;
    stiki_iv remote_iv;
    uint8_t crypt_key[KEY_LENGTH];
    uint8_t mac_key[KEY_LENGTH];
    unsigned long last_event;
} stiki_session;

stiki_session* sessions[STIKI_MAX_SESSION_COUNT];

//returns index in sessions[], -1 if none found
int8_t search_session_idx(uint16_t node_id);
uint8_t is_session_available(uint16_t node_id);
//set last_event to current timestamp
void update_last_active(uint16_t node_id);
//creates a new session
//returns the position in sessions[]. guaranteed to not be -1
int8_t create_session(uint16_t node_id);
void set_session_key(stiki_session *session, uint8_t *key);
void invalidate_session(uint16_t nodeid);

#endif /*SESSIONSTORE_H_*/
