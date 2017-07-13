
//#define PBC_DEBUG


#include "ibbe.h"
#include <stdio.h>
#include <time.h>

char S[MAX_RECEIVER][MAX_STRING_LENGTH];

void print_key(unsigned char *h)
{
    for(int i=0; i<32; i++)
        printf("%02X", h[i]);
    printf("\n");
}


int main(int argc, char** argv)
{
    printf("IBBE DEMO : \n");
    int i;
    clock_t time1, time2;
    for (i = 0; i < MAX_RECEIVER; i++)
    {
        sprintf(S[i], "test%d@mail.com", i+1);
    }

    PublicKey pubkey;
    MasterSecretKey prvkey;
    ShortPublicKey shortPubKey;

    setup_sgx_safe(&pubkey, &shortPubKey, &prvkey, argc, argv);

    UserPrivateKey usr13PriKey;
    extract_sgx_safe(prvkey, usr13PriKey, "test13@mail.com");

    for (int test=0; test < 5; test++)
    {
        Ciphertext cipher;
        BroadcastKey bKey;

        encrypt_sgx_safe(&bKey, &cipher, shortPubKey, prvkey, S, MAX_RECEIVER);
        printf("\nBROADCAST KEY : ");
        print_key(bKey);

        BroadcastKey adminBroadcastKey;
        decrypt_sgx_safe(&adminBroadcastKey, cipher, shortPubKey, prvkey,
            S, MAX_RECEIVER);
        printf("ADM DECR. KEY : ");
        print_key(adminBroadcastKey);


        BroadcastKey decryptedBroadcastKey;
        decrypt_with_key_sgx_safe(&decryptedBroadcastKey, cipher, shortPubKey, prvkey,
            usr13PriKey, "test13@mail.com", S, MAX_RECEIVER);
        printf("SGX DECR. KEY : ");
        print_key(decryptedBroadcastKey);

        BroadcastKey oldStyleBroadcastKey;
        decrypt_user_no_optimizations(&oldStyleBroadcastKey, cipher, pubkey,
            usr13PriKey, "test13@mail.com", S, MAX_RECEIVER);
        printf("OLD DECR. KEY : ");
        print_key(oldStyleBroadcastKey);

        BroadcastKey userBroadcastKey;
        decrypt_user(&userBroadcastKey, cipher, pubkey,
            usr13PriKey, "test13@mail.com", S, MAX_RECEIVER);
        printf("USR DECR. KEY : ");
        print_key(userBroadcastKey);
    }

    return 0;
}
