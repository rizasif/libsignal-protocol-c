#ifndef SIGNAL_PROTOCOL_HELPER_H
#define SIGNAL_PROTOCOL_HELPER_H

#include "signal_protocol.h"

int signal_protocol_helper_signal_crypto_random(uint8_t *data, size_t len, void *user_data);

int signal_protocol_helper_signal_hmac_sha256_init(signal_context *context, void **hmac_context, const uint8_t *key, size_t key_len);
int signal_protocol_helper_signal_hmac_sha256_update(signal_context *context, void *hmac_context, const uint8_t *data, size_t data_len);
int signal_protocol_helper_signal_hmac_sha256_final(signal_context *context, void *hmac_context, signal_buffer **output);
void signal_protocol_helper_signal_hmac_sha256_cleanup(signal_context *context, void *hmac_context);

int signal_protocol_helper_signal_sha512_digest_init(signal_context *context, void **digest_context);
int signal_protocol_helper_signal_sha512_digest_update(signal_context *context, void *digest_context, const uint8_t *data, size_t data_len);
int signal_protocol_helper_signal_sha512_digest_final(signal_context *context, void *digest_context, signal_buffer **output);
void signal_protocol_helper_signal_sha512_digest_cleanup(signal_context *context, void *digest_context);


int signal_protocol_helper_signal_encrypt(signal_context *context,
        signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len);

int signal_protocol_helper_signal_decrypt(signal_context *context,
        signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len);

void signal_protocol_helper_intialize_crypto_provider(signal_crypto_provider *provider, int user_id);

#endif