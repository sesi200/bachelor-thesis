#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "stiki-main.h"
#include "lib/aes-128.h"
#include "lib/random.h"

#ifndef INITIAL_MASTER_KEY
#define INITIAL_MASTER_KEY {0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77}
#endif /*INITIAL_MASTER_KEY*/

//used to derive the encryption key from the session key
extern const uint8_t CRYPT_DERIVE_BLOCK[];
//used to derive the key for computing the MAC from the session key
extern const uint8_t INTEG_DERIVE_BLOCK[];

//call generate_... to get a new random iv/nonce.
void generate_iv(stiki_iv *dest);//iv->is_set will be true afterwards
void generate_nonce(stiki_nonce *dest);

//encrypts the message in place using CTR mode
//expects:
//      len(key) == BLOCK_SIZE
//      iv has correct message counter set
void encrypt_message(uint8_t *message, const uint16_t len, stiki_iv *iv, const uint8_t *key);

//computes MAC according to RFC 4493, writes BLOCK_SIZE bytes to *out
void compute_mac(uint8_t *out, const uint8_t *in, const uint16_t len, const uint8_t *key);

//checks if the MAC is computed correctly
//no mac_len necessary because it always has size BLOCK_SIZE
uint8_t mac_is_valid(const uint8_t *mac_to_check, const uint8_t *in, const uint16_t input_len, const uint8_t *key);

#endif /*CRYPTO_H_*/
