#ifndef SIGNAL_PROTOCOL_HELPER_H
#define SIGNAL_PROTOCOL_HELPER_H

#include "signal_protocol.h"

int signal_protocol_helper_signal_crypto_random(uint8_t *data, size_t len, void *user_data);

int signal_protocol_helper_signal_hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
int signal_protocol_helper_signal_hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
int signal_protocol_helper_signal_hmac_sha256_final(void *hmac_context, signal_buffer **output, void *user_data);
void signal_protocol_helper_signal_hmac_sha256_cleanup(void *hmac_context, void *user_data);

int signal_protocol_helper_signal_sha512_digest_init(void **digest_context, void *user_data);
int signal_protocol_helper_signal_sha512_digest_update(void *digest_context, const uint8_t *data, size_t data_len, void *user_data);
int signal_protocol_helper_signal_sha512_digest_final(void *digest_context, signal_buffer **output, void *user_data);
void signal_protocol_helper_signal_sha512_digest_cleanup(void *digest_context, void *user_data);


int signal_protocol_helper_signal_encrypt(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data);

int signal_protocol_helper_signal_decrypt(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data);

void signal_protocol_helper_intialize_crypto_provider(signal_crypto_provider *provider, int user_id);

/* session store */
int signal_protocol_helper_session_store_load_session(signal_buffer **record, const signal_protocol_address *address, void *user_data);
int signal_protocol_helper_session_store_get_sub_device_sessions(signal_int_list **sessions, const char *name, size_t name_len, void *user_data);
int signal_protocol_helper_session_store_store_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, void *user_data);
int signal_protocol_helper_session_store_contains_session(const signal_protocol_address *address, void *user_data);
int signal_protocol_helper_session_store_delete_session(const signal_protocol_address *address, void *user_data);
int signal_protocol_helper_session_store_delete_all_sessions(const char *name, size_t name_len, void *user_data);
void signal_protocol_helper_session_store_destroy(void *user_data);

void setup_signal_protocol_helper_session_store(signal_protocol_store_context *context);

#endif