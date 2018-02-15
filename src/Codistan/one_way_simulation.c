#ifndef CODISTAN_ONE_WAY_SIMULATION
#define CODISTAN_ONE_WAY_SIMULATION

#include <stdio.h>
#include <check.h>
#include <sys/time.h>
#include <pthread.h>

#include "signal_protocol.h"
#include "signal_protocol_helper.h"

/*
* This Simulation sends a message between two identities Irene and Roy
* Irene: Initiatior
* Roy: Recepient
*/

// Irene
int user_id_irene;

signal_context *global_context_irene;
ratchet_identity_key_pair *identity_key_pair_irene;
uint32_t registration_id_irene;
signal_protocol_key_helper_pre_key_list_node *pre_keys_head_irene;
session_signed_pre_key *signed_pre_key_irene;

signal_crypto_provider provider_irene;
signal_protocol_session_store session_store_irene;
signal_protocol_pre_key_store pre_key_store_irene;
signal_protocol_signed_pre_key_store signed_pre_key_store_irene;
signal_protocol_identity_key_store identity_key_store_irene;

// Roy
// int user_id_roy;
// signal_protocol_address address_roy;

// signal_context *global_context_roy;
// ratchet_identity_key_pair *identity_key_pair_roy;
// uint32_t registration_id_roy;
// signal_protocol_key_helper_pre_key_list_node *pre_keys_head_roy;
// session_signed_pre_key *signed_pre_key_roy;

// signal_crypto_provider provider_roy;
// signal_protocol_session_store session_store_roy;
// signal_protocol_pre_key_store pre_key_store_roy;
// signal_protocol_signed_pre_key_store signed_pre_key_store_roy;
// signal_protocol_identity_key_store identity_key_store_roy;

/* Common Functions */
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

/*Main Functions Start*/

void Initialize(int user_id, 
                signal_crypto_provider *provider,
                signal_context **global_context)
{
    int result = 1; //flag for error check

    signal_protocol_helper_intialize_crypto_provider(provider, user_id);

    result = signal_context_create(global_context, &user_id);
    if(result != 0)
        printf("Context Creation Failed\n");

    result = signal_context_set_crypto_provider(*global_context, provider);
    if(result != 0)
        printf("Setting Crypto Provider Failed\n");

    result = signal_context_set_locking_functions(*global_context, lock_func, unlock_func);
    if(result != 0)
        printf("Setting Lock Functions Failed\n");

    if(result != 0)
        printf("Initialization Completed With Erros\n");
    else
        printf("Initialization Completed Successfully\n");
}

void ClientInstall( ratchet_identity_key_pair **identity_key_pair,
                    uint32_t **registration_id,
                    signal_protocol_key_helper_pre_key_list_node **pre_keys_head,
                    session_signed_pre_key **signed_pre_key,
                    signal_context **global_context){
    printf("Starting Client Installation\n");

    // signal_protocol_key_helper_generate_identity_key_pair(*identity_key_pair, *global_context);
    // printf("Identity Key Pair Generated\n");

    // signal_protocol_key_helper_generate_registration_id(registration_id, 0, *global_context);
    // printf("Registration ID Generated\n");

    // signal_protocol_key_helper_generate_pre_keys(pre_keys_head, 0, 100, *global_context);
    // printf("Pre Keys Generated\n");
    
    // signal_protocol_key_helper_generate_signed_pre_key(signed_pre_key, *identity_key_pair, 5, getCurrentEpochTime(), *global_context);
    // printf("Signed Pre Key Generated\n");

    /* Store identity_key_pair somewhere durable and safe. */
    /* Store registration_id somewhere durable and safe. */

    /* Store pre keys in the pre key store. */
    /* Store signed pre key in the signed pre key store. */

    printf("Client Installation Completed Successfully\n");
}

// void GenerateKeys(){
//     /* Create the data store context, and add all the callbacks to it */
//     signal_protocol_store_context *store_context;
//     signal_protocol_store_context_create(&store_context, global_context);
//     printf("Store Context Created\n");

//     setup_signal_protocol_helper_session_store(store_context);
//     printf("Session Store Created\n");

//     signal_protocol_store_context_set_session_store(store_context, &session_store);
//     printf("Session Store Context Set\n");

//     setup_signal_protocol_helper_pre_key_store(store_context);
//     printf("Pre Key Store Created\n");

//     signal_protocol_store_context_set_pre_key_store(store_context, &pre_key_store);
//     printf("Pre Key Store Context Set\n");
    
//     setup_signal_protocol_helper_signed_pre_key_store(store_context);
//     printf("Signed Pre Key Store Created\n");

//     signal_protocol_store_context_set_signed_pre_key_store(store_context, &signed_pre_key_store);
//     printf("Signed Pre Key Store Context Set\n");

//     setup_signal_protocol_helper_identity_key_store(store_context, global_context);
//     printf("Identity Key Store Created\n");

//     signal_protocol_store_context_set_identity_key_store(store_context, &identity_key_store);
//     printf("Identity Key Store Context Set\n");

//     printf("Key Generation Completed");
// }

/*Main Functions End*/

int main(void)
{
    printf("Starting One Way Simulation\n");

    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    printf("Setting Up Irene\n");
    user_id_irene = 1991;
    signal_protocol_address address = {
        "+14159998888", 12, 1
    };

    printf("Initializaing Irene\n");
    Initialize(user_id_irene, &provider_irene, &global_context_irene);

    printf("Installing Client Irene\n");
    ClientInstall(&identity_key_pair_irene, &registration_id_irene, &pre_keys_head_irene, &signed_pre_key_irene, &global_context_irene);

    // GenerateKeys();

    printf("Ending One Way Simulation\n");
    return 0;
}

#endif
