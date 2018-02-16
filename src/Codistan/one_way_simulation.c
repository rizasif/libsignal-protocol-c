#ifndef CODISTAN_ONE_WAY_SIMULATION
#define CODISTAN_ONE_WAY_SIMULATION

#include <stdio.h>
#include <check.h>
#include <sys/time.h>
#include <pthread.h>

#include "signal_protocol.h"
#include "signal_protocol_helper.h"

#include "curve.h"
#include "ratchet.h"

/*
* This Simulation sends a message between two identities Irene and Roy
* Irene: Initiatior
* Roy: Recepient
*/

/* Irene */
int user_id_irene;

signal_context *global_context_irene;
ratchet_identity_key_pair *identity_key_pair_irene;
uint32_t registration_id_irene;
signal_protocol_key_helper_pre_key_list_node *pre_keys_head_irene;
session_signed_pre_key *signed_pre_key_irene;

signal_protocol_store_context *store_context_irene;
signal_crypto_provider provider_irene;
signal_protocol_session_store session_store_irene;
signal_protocol_pre_key_store pre_key_store_irene;
signal_protocol_signed_pre_key_store signed_pre_key_store_irene;
signal_protocol_identity_key_store identity_key_store_irene;

/* Roy */
int user_id_roy;

signal_context *global_context_roy;
ratchet_identity_key_pair *identity_key_pair_roy;
uint32_t registration_id_roy;
signal_protocol_key_helper_pre_key_list_node *pre_keys_head_roy;
session_signed_pre_key *signed_pre_key_roy;

signal_protocol_store_context *store_context_roy;
signal_crypto_provider provider_roy;
signal_protocol_session_store session_store_roy;
signal_protocol_pre_key_store pre_key_store_roy;
signal_protocol_signed_pre_key_store signed_pre_key_store_roy;
signal_protocol_identity_key_store identity_key_store_roy;

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

    signal_protocol_key_helper_generate_identity_key_pair(identity_key_pair, *global_context);
    printf("Identity Key Pair Generated\n");

    signal_protocol_key_helper_generate_registration_id(registration_id, 0, *global_context);
    printf("Registration ID Generated\n");

    signal_protocol_key_helper_generate_pre_keys(pre_keys_head, 0, 100, *global_context);
    printf("Pre Keys Generated\n");
    
    signal_protocol_key_helper_generate_signed_pre_key(signed_pre_key, *identity_key_pair, 5, getCurrentEpochTime(), *global_context);
    printf("Signed Pre Key Generated\n");

    /* Store identity_key_pair somewhere durable and safe. */
    /* Store registration_id somewhere durable and safe. */

    /* Store pre keys in the pre key store. */
    /* Store signed pre key in the signed pre key store. */

    printf("Client Installation Completed Successfully\n");
}

void GenerateKeys(  signal_protocol_store_context **store_context,
                    signal_protocol_session_store *session_store,
                    signal_protocol_pre_key_store *pre_key_store,
                    signal_protocol_signed_pre_key_store *signed_pre_key_store,
                    signal_protocol_identity_key_store *identity_key_store,
                    signal_context **global_context){

    /* Create the data store context, and add all the callbacks to it */
    signal_protocol_store_context_create(store_context, *global_context);
    printf("Store Context Created\n");

    setup_signal_protocol_helper_session_store(*store_context);
    printf("Session Store Created\n");

    signal_protocol_store_context_set_session_store(*store_context, session_store);
    printf("Session Store Context Set\n");

    setup_signal_protocol_helper_pre_key_store(*store_context);
    printf("Pre Key Store Created\n");

    signal_protocol_store_context_set_pre_key_store(*store_context, pre_key_store);
    printf("Pre Key Store Context Set\n");
    
    setup_signal_protocol_helper_signed_pre_key_store(*store_context);
    printf("Signed Pre Key Store Created\n");

    signal_protocol_store_context_set_signed_pre_key_store(*store_context, signed_pre_key_store);
    printf("Signed Pre Key Store Context Set\n");

    setup_signal_protocol_helper_identity_key_store(*store_context, *global_context);
    printf("Identity Key Store Created\n");

    signal_protocol_store_context_set_identity_key_store(*store_context, identity_key_store);
    printf("Identity Key Store Context Set\n");

    printf("Key Generation Completed\n");
}

/*Main Functions End*/

int main(void)
{
    printf("Starting One Way Simulation\n");

    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    /* Irene Setup */
    printf("Setting Up Irene\n");
    user_id_irene = 1991;
    signal_protocol_address address_irene = {
        "+14159998888", 12, 1
    };
    printf("Initializaing Irene\n");
    Initialize(user_id_irene, &provider_irene, &global_context_irene);
    printf("Installing Client Irene\n");
    ClientInstall(&identity_key_pair_irene, &registration_id_irene, &pre_keys_head_irene, &signed_pre_key_irene, &global_context_irene);
    printf("Generating Keys Irene\n");
    GenerateKeys(&store_context_irene, &session_store_irene,&pre_key_store_irene, &signed_pre_key_store_irene, &identity_key_store_irene, &global_context_irene);

    /* Roy Setup */
    printf("Setting Up Roy\n");
    user_id_roy = 1992;
    signal_protocol_address address_roy = {
        "+14159998889", 12, 2
    };
    printf("Initializaing Roy\n");
    Initialize(user_id_roy, &provider_roy, &global_context_roy);
    printf("Installing Client Roy\n");
    ClientInstall(&identity_key_pair_roy, &registration_id_roy, &pre_keys_head_roy, &signed_pre_key_roy, &global_context_roy);
    printf("Generating Keys Roy\n");
    GenerateKeys(&store_context_roy, &session_store_roy,&pre_key_store_roy, &signed_pre_key_store_roy, &identity_key_store_roy, &global_context_roy);

    /*Building Session by Irene to Roy*/
    printf("Irene Building Session\n");
    session_builder *builder;
    session_builder_create(&builder, store_context_irene, &address_irene, global_context_irene);

    printf("----Irene Processing Pre Key Bundle----");

    int result = 0;

    uint32_t roy_pre_key_id = 1947;
    uint32_t roy_local_registration_id = 19911;
    result = signal_protocol_identity_get_local_registration_id(store_context_roy, &roy_local_registration_id);
    if(result != 0){
        printf("Local id Generation Failed\n");
    }

    ec_key_pair *roy_pre_key_pair = 0;
    result = curve_generate_key_pair(global_context_irene, &roy_pre_key_pair);
    if(result != 0){
        printf("Cureve Key Pair Generation Failed\n");
    }

    ratchet_identity_key_pair *roy_identity_key_pair = 0;
    result = signal_protocol_identity_get_key_pair(store_context_roy, &roy_identity_key_pair);
    if(result != 0){
        printf("Identity Key Pair Generation Failed\n");
    }

    ec_key_pair *roy_signed_pre_key = 0;
    result = curve_generate_key_pair(global_context_irene, &roy_signed_pre_key);
    if(result != 0){
        printf("Signed Pre-Key Generation Failed\n");
    }

    signal_buffer *roy_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&roy_signed_pre_key_public_serialized, ec_key_pair_get_public(roy_signed_pre_key));
    if(result != 0){
        printf("Signed Pre-Key Serialization Failed\n");
    }

    signal_buffer *signature = 0;
    result = curve_calculate_signature(global_context_irene, &signature,
            ratchet_identity_key_pair_get_private(roy_identity_key_pair),
            signal_buffer_data(roy_signed_pre_key_public_serialized),
            signal_buffer_len(roy_signed_pre_key_public_serialized));
    if(result != 0){
        printf("Curve Signature Generation Failed\n");
    }

    uint32_t roy_signed_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    session_pre_key_bundle *roy_pre_key_bundle = 0;
    result = session_pre_key_bundle_create(&roy_pre_key_bundle,
            roy_local_registration_id,
            address_roy.device_id, /* device ID */
            roy_pre_key_id, /* pre key ID */
            ec_key_pair_get_public(roy_pre_key_pair),
            roy_signed_pre_key_id, ec_key_pair_get_public(roy_signed_pre_key), 
            signal_buffer_data(signature), signal_buffer_len(signature), /* no signed pre key or signature */
            ratchet_identity_key_pair_get_public(roy_identity_key_pair));
    if(result != 0){
        printf("Pre-Key Bundle Generation Failed\n");
    }

    /* Build a session with a pre key retrieved from the server. */
    session_builder_process_pre_key_bundle(builder, roy_pre_key_bundle);

    printf("Ending One Way Simulation\n");
    return 0;
}

#endif
