#ifndef CODISTAN_TEST_SIGNAL_PROTOCOL
#define CODISTAN_TEST_SIGNAL_PROTOCOL

#include <stdio.h>
#include <check.h>

#include "signal_protocol.h"

signal_context *global_context;

void VoidCallBack(void){
    printf("VoidCallback Initiated\n");
}

int main(void)
{
    printf("Starting Protocol Test\n");

    int result = 1;

    result = signal_context_create(&global_context, &VoidCallBack);
    printf("Creating Signal Context Result: %i", result);

    // result = signal_context_set_crypto_provider(global_context, &provider);
    // if(result != 0)
    //     printf("Setting Crypto Provider Failed\n");

    // result = signal_context_set_locking_functions(global_context, lock_function, unlock_function);
    // if(result != 0)
    //     printf("Setting Lock Functions Failed\n");

    return 0;
}

#endif
