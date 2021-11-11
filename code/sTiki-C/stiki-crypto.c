#include "stiki-crypto.h"

const uint8_t CRYPT_DERIVE_BLOCK[BLOCK_SIZE] = {0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49};
const uint8_t INTEG_DERIVE_BLOCK[BLOCK_SIZE] = {0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70};

void generate_iv(stiki_iv *dest) {
    uint8_t i;
    unsigned short random;
    for (i = 0; i < IV_LENGTH/2; i++) {
        random = random_rand();
        dest->bytes[2*i] = (uint8_t)(random & 0xff);
        dest->bytes[2*i+1] = (uint8_t)(random >> 8);
    }
    dest->bytes[IV_LENGTH-3] = 0;//clear for msg counter
    dest->bytes[IV_LENGTH-2] = 0;//clear for msg counter
    dest->bytes[IV_LENGTH-1] = 0;//clear for block counter
    dest->is_set = 1;
}

void generate_nonce(stiki_nonce *dest) {
    uint8_t i;
    unsigned short random;
    for (i = 0; i < NONCE_LENGTH/2; i++) {
        random = random_rand();
        dest->bytes[2*i] = (uint8_t)(random & 0xff);
        dest->bytes[2*i+1] = (uint8_t)(random >> 8);
    }
}

void encrypt_message(uint8_t *message, const uint16_t len, stiki_iv *iv, const uint8_t *key) {

    uint8_t i;
    uint8_t encrypted_iv[BLOCK_SIZE] = {0};

    set_iv_block_counter(iv, 0);
    AES_128.set_key(key);

    for(i=0; i<len; ++i) {
        //generate a new encrypted_iv if needed
        if(i%BLOCK_SIZE == 0) {
            memcpy(encrypted_iv, iv->bytes, BLOCK_SIZE);
            AES_128.encrypt(encrypted_iv);
            //increase last so the first encrypted_iv is done with block counter = 0
            inc_iv_block_counter(iv);
        }

        //actual encryption step
        message[i] ^= encrypted_iv[i%BLOCK_SIZE];
    }
}

void sub_derive(uint8_t *in) {
    uint8_t msb = ((in[0]&0x80)!=0);

    //shift entire array 1 bit to the left
    uint8_t i;
    for (i=0; i < BLOCK_SIZE-1; ++i) {
        in[i] = ((in[i]<<1) | (in[i+1]>>7));
    }
    in[BLOCK_SIZE-1] = (in[BLOCK_SIZE-1]<<1);

    if(msb) {
        in[BLOCK_SIZE-1] ^= 0x87;
    }
}

void xor(uint8_t *out, const uint8_t *in1, const uint8_t *in2) {
    uint8_t i;
    for (i = 0; i < BLOCK_SIZE; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

//fills the block with 10*
void pad(uint8_t *out, const uint8_t start) {
    uint8_t i;
    out[start] = 0x80;
    for (i = start+1; i < BLOCK_SIZE; i++) {
        out[i] = 0;
    }
}

void compute_mac(uint8_t *out, const uint8_t *in, const uint16_t len, const uint8_t *_key) {
    uint8_t key[BLOCK_SIZE] = {0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12};
    AES_128.set_key(key);
    const uint8_t *pos;
    uint8_t padding_needed;
    uint8_t tmp_block[BLOCK_SIZE];

    //padding is needed if a) we have no data or b) the last block is not filled entirely
    padding_needed = (len==0 || len%BLOCK_SIZE != 0);

    //generate subkey1, subkey2 might be generated later (only if needed)
    uint8_t subkey[BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    AES_128.encrypt(subkey);
    sub_derive(subkey);

    memset(out, 0, BLOCK_SIZE);
    //handle all but last block
    for(pos = in; pos < in+len-BLOCK_SIZE; pos+=BLOCK_SIZE) {
        xor(out, out, pos);
        AES_128.encrypt(out);
    }

    //handle last block
    memcpy(tmp_block, pos, (len%BLOCK_SIZE==0 ? BLOCK_SIZE : len%BLOCK_SIZE));
    if (padding_needed) {
        sub_derive(subkey);
        pad(tmp_block, (len%BLOCK_SIZE==0 ? BLOCK_SIZE : len%BLOCK_SIZE));
    }
    xor(tmp_block, tmp_block, subkey);

    //final computations
    xor(out, tmp_block, out);
    AES_128.encrypt(out);
}

uint8_t mac_is_valid(const uint8_t *mac_to_check, const uint8_t *data, const uint16_t data_len, const uint8_t *key) {
    uint8_t computed_mac[BLOCK_SIZE];
    compute_mac(computed_mac, data, data_len, key);

    return 0 == memcmp(mac_to_check, computed_mac, 16);
}