#include "sessionstore.h"

MEMB(session_store, stiki_session, STIKI_MAX_SESSION_COUNT);

uint8_t get_free_slot_idx();
void free_session(int8_t idx);
uint8_t is_timed_out(stiki_session *s);

int8_t search_session_idx(uint16_t node_id) {
    int8_t i;
    for (i = 0; i < STIKI_MAX_SESSION_COUNT; ++i) {
        if(!sessions[i]) {
            continue;
        }

        //remove timed out sessions
        if(is_timed_out(sessions[i])) {
            free_session(i);
            continue;
        }

        //find correct sessions
        if(sessions[i]->node_id == node_id) {
            return i;
        }
    }
    //no matching session found
    return -1;
}

uint8_t is_session_available(uint16_t node_id) {
    return search_session_idx(node_id) >= 0;
}

uint8_t get_free_slot_idx() {
    uint8_t oldest_session = 0;
    uint8_t i;
    for (i = 0; i < STIKI_MAX_SESSION_COUNT; i++) {
        //check for free slot
        if (sessions[i] == NULL) {
            return i;
        }
        //check if sessions[i] is older
        if (sessions[i]->last_event < sessions[oldest_session]->last_event) {
            oldest_session = i;
        }
    }
    return oldest_session;
}

void free_session(int8_t idx) {
    if (idx >= STIKI_MAX_SESSION_COUNT) return;
    if (idx < 0) return;

    if(sessions[idx] == NULL) {
        //session does not exist
        return;
    }
    memb_free(&session_store, sessions[idx]);
    sessions[idx] = NULL;
}

void update_last_active(uint16_t node_id) {
    if (is_session_available(node_id)) {
        stiki_session* session = sessions[search_session_idx(node_id)];
        session->last_event = clock_seconds();
    }
}

int8_t create_session(uint16_t node_id) {
    int8_t slot = get_free_slot_idx();

    if (sessions[slot] == NULL) {
        sessions[slot] = memb_alloc(&session_store);
    }
    memset(sessions[slot], 0, sizeof(stiki_session));

    sessions[slot]->node_id = node_id;
    update_last_active(node_id);
    return slot;
}

uint8_t is_timed_out(stiki_session *s) {
    return clock_seconds() > (s->last_event + SESSION_TIMEOUT);
}

void set_session_key(stiki_session *session, uint8_t *key) {
    memcpy(session->crypt_key, CRYPT_DERIVE_BLOCK, KEY_LENGTH);
    memcpy(session->mac_key, INTEG_DERIVE_BLOCK, KEY_LENGTH);

    AES_128.set_key(key);
    AES_128.encrypt(session->crypt_key);
    AES_128.encrypt(session->mac_key);
}

void invalidate_session(uint16_t node_id) {
    free_session(search_session_idx(node_id));
}