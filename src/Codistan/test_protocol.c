#ifndef CODISTAN_TEST_SIGNAL_PROTOCOL
#define CODISTAN_TEST_SIGNAL_PROTOCOL

#include <stdio.h>
#include <check.h>
#include <sys/time.h>
#include <pthread.h>

#include "signal_protocol.h"
#include "signal_protocol_helper.h"

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

    result = signal_context_create(&global_context, &user_id);
    if(result != 0)
        printf("Context Creation Failed\n");

    result = signal_context_set_crypto_provider(global_context, &provider);
    if(result != 0)
        printf("Setting Crypto Provider Failed\n");

    result = signal_context_set_locking_functions(global_context, lock_func, unlock_func);
    if(result != 0)
        printf("Setting Lock Functions Failed\n");

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
