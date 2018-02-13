#ifndef CODISTAN_TEST_SIGNAL_PROTOCOL
#define CODISTAN_TEST_SIGNAL_PROTOCOL

#include <stdio.h>
#include <check.h>
#include <sys/time.h>
#include <pthread.h>

#include "signal_protocol.h"

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Signal Protocol
signal_context *global_context;
ratchet_identity_key_pair *identity_key_pair;
uint32_t registration_id;
signal_protocol_key_helper_pre_key_list_node *pre_keys_head;
session_signed_pre_key *signed_pre_key;
signal_crypto_provider provider;

// Customizations
int user_id;

pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

// void intialize_crypto_provider(){
//     provider.random_func = signal_crypto_random;
//     provider.hmac_sha256_init_func = signal_hmac_sha256_init;
//     provider.hmac_sha256_update_func = signal_hmac_sha256_update;
//     provider.hmac_sha256_final_func = signal_hmac_sha256_final;
//     provider.hmac_sha256_cleanup_func = signal_hmac_sha256_cleanup;
//     provider.sha512_digest_init_func = signal_sha512_digest_init;
//     provider.sha512_digest_update_func = signal_sha512_digest_update;
//     provider.sha512_digest_final_func = signal_sha512_digest_final;
//     provider.sha512_digest_cleanup_func = signal_sha512_digest_cleanup;
//     provider.encrypt_func = signal_encrypt;
//     provider.decrypt_func = signal_decrypt;
//     provider.user_data = user_id;
// }

void lock_func(void *user_data)
{
    pthread_mutex_lock(&global_mutex);
}

void unlock_func(void *user_data)
{
    pthread_mutex_unlock(&global_mutex);
}

unsigned long long getCurrentEpochTime(){
    struct timeval tv;

    gettimeofday(&tv, NULL);

    unsigned long long millisecondsSinceEpoch =
        (unsigned long long)(tv.tv_sec) * 1000 +
        (unsigned long long)(tv.tv_usec) / 1000;

    // printf("%llu\n", millisecondsSinceEpoch);
    return millisecondsSinceEpoch;
}

/*provider code start*/
int signal_protocol_helper_signal_crypto_random(signal_context *context, uint8_t *data, size_t len){
    if(RAND_bytes(data, len)) {
        return 0;
    }
    else {
        return SG_ERR_UNKNOWN;
    }
}

int signal_protocol_helper_signal_hmac_sha256_init(signal_context *context, void **hmac_context, const uint8_t *key, size_t key_len){
    #if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    HMAC_CTX *ctx = HMAC_CTX_new();
    if(!ctx) {
        return SG_ERR_NOMEM;
    }
#else
    HMAC_CTX *ctx = malloc(sizeof(HMAC_CTX));
    if(!ctx) {
        return SG_ERR_NOMEM;
    }
    HMAC_CTX_init(ctx);
#endif

    *hmac_context = ctx;

    if(HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), 0) != 1) {
        return SG_ERR_UNKNOWN;
    }

    return 0;
}

int signal_protocol_helper_signal_hmac_sha256_update(signal_context *context, void *hmac_context, const uint8_t *data, size_t data_len){
    HMAC_CTX *ctx = hmac_context;
    int result = HMAC_Update(ctx, data, data_len);
    return (result == 1) ? 0 : -1;
}

int signal_protocol_helper_signal_hmac_sha256_final(signal_context *context, void *hmac_context, signal_buffer **output){
    int result = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC_CTX *ctx = hmac_context;

    if(HMAC_Final(ctx, md, &len) != 1) {
        return SG_ERR_UNKNOWN;
    }

    signal_buffer *output_buffer = signal_buffer_create(md, len);
    if(!output_buffer) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    *output = output_buffer;

complete:
    return result;
}

void signal_protocol_helper_signal_hmac_sha256_cleanup(signal_context *context, void *hmac_context){
    if(hmac_context) {
        HMAC_CTX *ctx = hmac_context;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        HMAC_CTX_free(ctx);
#else
        HMAC_CTX_cleanup(ctx);
        free(ctx);
#endif
    }
}

const EVP_CIPHER *aes_cipher(int cipher, size_t key_len)
{
    if(cipher == SG_CIPHER_AES_CBC_PKCS5) {
        if(key_len == 16) {
            return EVP_aes_128_cbc();
        }
        else if(key_len == 24) {
            return EVP_aes_192_cbc();
        }
        else if(key_len == 32) {
            return EVP_aes_256_cbc();
        }
    }
    else if(cipher == SG_CIPHER_AES_CTR_NOPADDING) {
        if(key_len == 16) {
            return EVP_aes_128_ctr();
        }
        else if(key_len == 24) {
            return EVP_aes_192_ctr();
        }
        else if(key_len == 32) {
            return EVP_aes_256_ctr();
        }
    }
    return 0;
}

int signal_protocol_helper_signal_sha512_digest_init(signal_context *context, void **digest_context){
    int result = 0;
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_create();
    if(!ctx) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result = EVP_DigestInit_ex(ctx, EVP_sha512(), 0);
    if(result == 1) {
        result = SG_SUCCESS;
    }
    else {
        result = SG_ERR_UNKNOWN;
    }

complete:
    if(result < 0) {
        if(ctx) {
            EVP_MD_CTX_destroy(ctx);
        }
    }
    else {
        *digest_context = ctx;
    }
    return result;
}

int signal_protocol_helper_signal_sha512_digest_update(signal_context *context, void *digest_context, const uint8_t *data, size_t data_len){
    EVP_MD_CTX *ctx = digest_context;

    int result = EVP_DigestUpdate(ctx, data, data_len);

    return (result == 1) ? SG_SUCCESS : SG_ERR_UNKNOWN;
}

int signal_protocol_helper_signal_sha512_digest_final(signal_context *context, void *digest_context, signal_buffer **output){
    int result = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = digest_context;

    result = EVP_DigestFinal_ex(ctx, md, &len);
    if(result == 1) {
        result = SG_SUCCESS;
    }
    else {
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    result = EVP_DigestInit_ex(ctx, EVP_sha512(), 0);
    if(result == 1) {
        result = SG_SUCCESS;
    }
    else {
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    signal_buffer *output_buffer = signal_buffer_create(md, len);
    if(!output_buffer) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    *output = output_buffer;

complete:
    return result;
}

void signal_protocol_helper_signal_sha512_digest_cleanup(signal_context *context, void *digest_context){
    EVP_MD_CTX *ctx = digest_context;
    EVP_MD_CTX_destroy(ctx);
}

int signal_protocol_helper_signal_encrypt(signal_context *context,
        signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len)
{
    int result = 0;
    EVP_CIPHER_CTX *ctx = 0;
    uint8_t *out_buf = 0;

    const EVP_CIPHER *evp_cipher = aes_cipher(cipher, key_len);
    if(!evp_cipher) {
        fprintf(stderr, "invalid AES mode or key size: %zu\n", key_len);
        return SG_ERR_UNKNOWN;
    }

    if(iv_len != 16) {
        fprintf(stderr, "invalid AES IV size: %zu\n", iv_len);
        return SG_ERR_UNKNOWN;
    }

    if(plaintext_len > INT_MAX - EVP_CIPHER_block_size(evp_cipher)) {
        fprintf(stderr, "invalid plaintext length: %zu\n", plaintext_len);
        return SG_ERR_UNKNOWN;
    }

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
#else
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    if(!ctx) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    EVP_CIPHER_CTX_init(ctx);
#endif

    result = EVP_EncryptInit_ex(ctx, evp_cipher, 0, key, iv);
    if(!result) {
        fprintf(stderr, "cannot initialize cipher\n");
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    if(cipher == SG_CIPHER_AES_CTR_NOPADDING) {
        result = EVP_CIPHER_CTX_set_padding(ctx, 0);
        if(!result) {
            fprintf(stderr, "cannot set padding\n");
            result = SG_ERR_UNKNOWN;
            goto complete;
        }
    }

    out_buf = malloc(sizeof(uint8_t) * (plaintext_len + EVP_CIPHER_block_size(evp_cipher)));
    if(!out_buf) {
        fprintf(stderr, "cannot allocate output buffer\n");
        result = SG_ERR_NOMEM;
        goto complete;
    }

    int out_len = 0;
    result = EVP_EncryptUpdate(ctx,
        out_buf, &out_len, plaintext, plaintext_len);
    if(!result) {
        fprintf(stderr, "cannot encrypt plaintext\n");
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    int final_len = 0;
    result = EVP_EncryptFinal_ex(ctx, out_buf + out_len, &final_len);
    if(!result) {
        fprintf(stderr, "cannot finish encrypting plaintext\n");
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    *output = signal_buffer_create(out_buf, out_len + final_len);

complete:
    if(ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(ctx);
        free(ctx);
#endif
    }
    if(out_buf) {
        free(out_buf);
    }
    return result;
}

int signal_protocol_helper_signal_decrypt(signal_context *context,
        signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len)
{
    int result = 0;
    EVP_CIPHER_CTX *ctx = 0;
    uint8_t *out_buf = 0;

    const EVP_CIPHER *evp_cipher = aes_cipher(cipher, key_len);
    if(!evp_cipher) {
        fprintf(stderr, "invalid AES mode or key size: %zu\n", key_len);
        return SG_ERR_INVAL;
    }

    if(iv_len != 16) {
        fprintf(stderr, "invalid AES IV size: %zu\n", iv_len);
        return SG_ERR_INVAL;
    }

    if(ciphertext_len > INT_MAX - EVP_CIPHER_block_size(evp_cipher)) {
        fprintf(stderr, "invalid ciphertext length: %zu\n", ciphertext_len);
        return SG_ERR_UNKNOWN;
    }

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
#else
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    if(!ctx) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    EVP_CIPHER_CTX_init(ctx);
#endif

    result = EVP_DecryptInit_ex(ctx, evp_cipher, 0, key, iv);
    if(!result) {
        fprintf(stderr, "cannot initialize cipher\n");
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    if(cipher == SG_CIPHER_AES_CTR_NOPADDING) {
        result = EVP_CIPHER_CTX_set_padding(ctx, 0);
        if(!result) {
            fprintf(stderr, "cannot set padding\n");
            result = SG_ERR_UNKNOWN;
            goto complete;
        }
    }

    out_buf = malloc(sizeof(uint8_t) * (ciphertext_len + EVP_CIPHER_block_size(evp_cipher)));
    if(!out_buf) {
        fprintf(stderr, "cannot allocate output buffer\n");
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    int out_len = 0;
    result = EVP_DecryptUpdate(ctx,
        out_buf, &out_len, ciphertext, ciphertext_len);
    if(!result) {
        fprintf(stderr, "cannot decrypt ciphertext\n");
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    int final_len = 0;
    result = EVP_DecryptFinal_ex(ctx, out_buf + out_len, &final_len);
    if(!result) {
        fprintf(stderr, "cannot finish decrypting ciphertext\n");
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    *output = signal_buffer_create(out_buf, out_len + final_len);

complete:
    if(ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(ctx);
        free(ctx);
#endif
    }
    if(out_buf) {
        free(out_buf);
    }
    return result;
}

void signal_protocol_helper_intialize_crypto_provider(signal_crypto_provider *provider, int user_id){
    provider->random_func = signal_protocol_helper_signal_crypto_random;
    provider->hmac_sha256_init_func = signal_protocol_helper_signal_hmac_sha256_init;
    provider->hmac_sha256_update_func = signal_protocol_helper_signal_hmac_sha256_update;
    provider->hmac_sha256_final_func = signal_protocol_helper_signal_hmac_sha256_final;
    provider->hmac_sha256_cleanup_func = signal_protocol_helper_signal_hmac_sha256_cleanup;
    provider->sha512_digest_init_func = signal_protocol_helper_signal_sha512_digest_init;
    provider->sha512_digest_update_func = signal_protocol_helper_signal_sha512_digest_update;
    provider->sha512_digest_final_func = signal_protocol_helper_signal_sha512_digest_final;
    provider->sha512_digest_cleanup_func = signal_protocol_helper_signal_sha512_digest_cleanup;
    provider->encrypt_func = signal_protocol_helper_signal_encrypt;
    provider->decrypt_func = signal_protocol_helper_signal_decrypt;
    provider->user_data = user_id;
}
/*provider code end*/

/*Start Session Store*/

int test_session_store_load_session(signal_buffer **record, const signal_protocol_address *address, void *user_data){return 0;}
int test_session_store_get_sub_device_sessions(signal_int_list **sessions, const char *name, size_t name_len, void *user_data){return 0;}
int test_session_store_store_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, void *user_data){return 0;}
int test_session_store_contains_session(const signal_protocol_address *address, void *user_data){return 0;}
int test_session_store_delete_session(const signal_protocol_address *address, void *user_data){return 0;}
int test_session_store_delete_all_sessions(const char *name, size_t name_len, void *user_data){return 0;}
void test_session_store_destroy(void *user_data){}
void setup_test_session_store(signal_protocol_store_context *context){}

signal_protocol_session_store session_store = {
        .load_session_func = test_session_store_load_session,
        .get_sub_device_sessions_func = test_session_store_get_sub_device_sessions,
        .store_session_func = test_session_store_store_session,
        .contains_session_func = test_session_store_contains_session,
        .delete_session_func = test_session_store_delete_session,
        .delete_all_sessions_func = test_session_store_delete_all_sessions,
        .destroy_func = test_session_store_destroy,
        .user_data = 0
    };
/*End Session Store*/

/*Start Signed pre key store*/
int test_signed_pre_key_store_load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data){return 0;}
int test_signed_pre_key_store_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data){return 0;}
int test_signed_pre_key_store_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data){return 0;}
int test_signed_pre_key_store_remove_signed_pre_key(uint32_t signed_pre_key_id, void *user_data){return 0;}
void test_signed_pre_key_store_destroy(void *user_data){}

signal_protocol_signed_pre_key_store signed_pre_key_store = {
            .load_signed_pre_key = test_signed_pre_key_store_load_signed_pre_key,
            .store_signed_pre_key = test_signed_pre_key_store_store_signed_pre_key,
            .contains_signed_pre_key = test_signed_pre_key_store_contains_signed_pre_key,
            .remove_signed_pre_key = test_signed_pre_key_store_remove_signed_pre_key,
            .destroy_func = test_signed_pre_key_store_destroy,
            .user_data = 0
    };
/*End Signed pre key store*/

/*Start Pre Key Store*/
int test_pre_key_store_load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data){return 0;}
int test_pre_key_store_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data){return 0;}
int test_pre_key_store_contains_pre_key(uint32_t pre_key_id, void *user_data){return 0;}
int test_pre_key_store_remove_pre_key(uint32_t pre_key_id, void *user_data){return 0;}
void test_pre_key_store_destroy(void *user_data){}

signal_protocol_pre_key_store pre_key_store = {
        .load_pre_key = test_pre_key_store_load_pre_key,
        .store_pre_key = test_pre_key_store_store_pre_key,
        .contains_pre_key = test_pre_key_store_contains_pre_key,
        .remove_pre_key = test_pre_key_store_remove_pre_key,
        .destroy_func = test_pre_key_store_destroy,
        .user_data = 0
    };
/*End Pre Key Store*/

/*Start Identity Key Store*/
int test_identity_key_store_get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data){return 0;}
int test_identity_key_store_get_local_registration_id(void *user_data, uint32_t *registration_id){return 0;}
int test_identity_key_store_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data){return 0;}
int test_identity_key_store_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data){return 0;}
void test_identity_key_store_destroy(void *user_data){}

signal_protocol_identity_key_store identity_key_store = {
            .get_identity_key_pair = test_identity_key_store_get_identity_key_pair,
            .get_local_registration_id = test_identity_key_store_get_local_registration_id,
            .save_identity = test_identity_key_store_save_identity,
            .is_trusted_identity = test_identity_key_store_is_trusted_identity,
            .destroy_func = test_identity_key_store_destroy,
            .user_data = 0
    };
/*End Identity Key Store*/

/*Main Functions Start*/

void Initialize(){
    int result = 1; //flag for error check

    signal_protocol_helper_intialize_crypto_provider(&provider, user_id);
    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    // result = signal_context_create(&global_context, &user_id);
    // if(result != 0)
    //     printf("Context Creation Failed\n");

    // result = signal_context_set_crypto_provider(&global_context, &provider);
    // if(result != 0)
    //     printf("Setting Crypto Provider Failed\n");

    // result = signal_context_set_locking_functions(&global_context, lock_func, unlock_func);
    // if(result != 0)
    //     printf("Setting Lock Functions Failed\n");

    if(result != 0)
        printf("Initialization Completed With Erros\n");
    else
        printf("Initialization Completed Successfully\n");
}

void ClientInstall(){
    signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, &global_context);
    printf("Identity Key Pair Generated");

    // signal_protocol_key_helper_generate_registration_id(&registration_id, 0, global_context);
    // signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, 0, 100, global_context);
    // signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, 5, getCurrentEpochTime(), global_context);

    /* Store identity_key_pair somewhere durable and safe. */
    /* Store registration_id somewhere durable and safe. */

    /* Store pre keys in the pre key store. */
    /* Store signed pre key in the signed pre key store. */
}
/*Main Functions End*/

int main(void)
{
    printf("Starting Protocol Test\n");

    user_id = 1992;

    Initialize();
    
    // ClientInstall();

    // /* Create the data store context, and add all the callbacks to it */
    // signal_protocol_store_context *store_context;
    // signal_protocol_store_context_create(&store_context, global_context);
    // signal_protocol_store_context_set_session_store(store_context, &session_store);
    // signal_protocol_store_context_set_pre_key_store(store_context, &pre_key_store);
    // signal_protocol_store_context_set_signed_pre_key_store(store_context, &signed_pre_key_store);
    // signal_protocol_store_context_set_identity_key_store(store_context, &identity_key_store);

    // /* Instantiate a session_builder for a recipient address. */
    // signal_protocol_address address = {
    //     "+14159998888", 12, 1
    // };
    // session_builder *builder;
    // session_builder_create(&builder, store_context, &address, global_context);

    /*Server Job*/
    

    /* Build a session with a pre key retrieved from the server. */
    // session_builder_process_pre_key_bundle(builder, retrieved_pre_key);

    // /* Create the session cipher and encrypt the message */
    // session_cipher *cipher;
    // session_cipher_create(&cipher, store_context, &address, global_context);

    // ciphertext_message *encrypted_message;
    // session_cipher_encrypt(cipher, message, message_len, &encrypted_message);

    // // /* Get the serialized content and deliver it */
    // signal_buffer *serialized = ciphertext_message_get_serialized(encrypted_message);

    // deliver(signal_buffer_data(serialized), signal_buffer_len(serialized));

    // // /* Cleanup */
    // SIGNAL_UNREF(encrypted_message);
    // session_cipher_free(cipher);
    // session_builder_free(builder);
    // signal_protocol_store_context_destroy(store_context);

    printf("Ending Protocol Test\n");
    return 0;
}

#endif
