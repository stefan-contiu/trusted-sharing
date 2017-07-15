#include "ibbe.h"
#include "spibbe.h"
#include <stdio.h>
#include <time.h>


void print_key(unsigned char *h)
{
    for(int i=0; i<32; i++)
        printf("%02X", h[i]);
    printf("\n");
}

int bvt_ibbe(int argc, char** argv)
{
    int group_size = 1000;
    char S[group_size][MAX_STRING_LENGTH];

    printf("IBBE DEMO : \n");

    int i;
    clock_t time1, time2;
    for (i = 0; i < group_size; i++)
    {
        sprintf(S[i], "test%d@mail.com", i+1);
    }

    PublicKey pubkey;
    MasterSecretKey prvkey;
    ShortPublicKey shortPubKey;

    setup_sgx_safe(&pubkey, &shortPubKey, &prvkey,
        group_size, argc, argv);

    UserPrivateKey usr13PriKey;
    extract_sgx_safe(prvkey, usr13PriKey, "test13@mail.com");

    for (int test=0; test < 5; test++)
    {
        Ciphertext cipher;
        BroadcastKey bKey;

        encrypt_sgx_safe(&bKey, &cipher, shortPubKey, prvkey, S, group_size);
        printf("\nBROADCAST KEY : ");
        print_key(bKey);

        BroadcastKey adminBroadcastKey;
        decrypt_sgx_safe(&adminBroadcastKey, cipher, shortPubKey, prvkey,
            S, group_size);
        printf("ADM DECR. KEY : ");
        print_key(adminBroadcastKey);

        BroadcastKey decryptedBroadcastKey;
        decrypt_with_key_sgx_safe(&decryptedBroadcastKey, cipher, shortPubKey, prvkey,
            usr13PriKey, "test13@mail.com", S, group_size);
        printf("SGX DECR. KEY : ");
        print_key(decryptedBroadcastKey);

        BroadcastKey oldStyleBroadcastKey;
        decrypt_user_no_optimizations(&oldStyleBroadcastKey, cipher, pubkey,
            usr13PriKey, "test13@mail.com", S, group_size);
        printf("OLD DECR. KEY : ");
        print_key(oldStyleBroadcastKey);

        BroadcastKey userBroadcastKey;
        decrypt_user(&userBroadcastKey, cipher, pubkey,
            usr13PriKey, "test13@mail.com", S, group_size);
        printf("USR DECR. KEY : ");
        print_key(userBroadcastKey);
    }
}

int bvt_spibbe(int argc, char** argv)
{
    int partition_max_size = 1000;
    int group_size = 10000;
    char S[group_size][MAX_STRING_LENGTH];

    int i;
    clock_t time1, time2;
    for (i = 0; i < group_size; i++)
    {
        sprintf(S[i], "test%d@mail.com", i+1);
    }

    PublicKey pubkey;
    MasterSecretKey prvkey;
    ShortPublicKey shortPubKey;

    setup_sgx_safe(&pubkey, &shortPubKey, &prvkey,
        partition_max_size + 1, argc, argv);

    BroadcastKey* bKeys;
    Ciphertext* ciphers;

    struct timespec start, finish;
    double elapsed;

    clock_gettime(CLOCK_MONOTONIC, &start);
    create_group(&bKeys, &ciphers, shortPubKey, prvkey, S, group_size, partition_max_size);
    clock_gettime(CLOCK_MONOTONIC, &finish);

    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("Create group took : %f s\n", elapsed);

    // admin_decrypt(bKeys[0], ciphers[0], shortPubKey, prvkey, )
    //add_user_sgx_safe(Ciphertext *cipher, MasterSecretKey msk, char* id);

    return 0;
}

int main(int argc, char** argv)
{
    //bvt_ibbe(argc, argv);
    //bvt_spibbe(argc, argv);
    return 0;
}
