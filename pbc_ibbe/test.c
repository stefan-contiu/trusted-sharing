
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
    //UserPrivateKey idkey[MAX_RECEIVER+1];

    setup_sgx_safe(&pubkey, &shortPubKey, &prvkey, argc, argv);

    Ciphertext cipher;
    BroadcastKey bKey;

    struct timespec start, finish;
    double elapsed;
    clock_gettime(CLOCK_MONOTONIC, &start);

    encrypt_sgx_safe(pubkey, &bKey, &cipher, shortPubKey, prvkey, S, MAX_RECEIVER);
    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("BDCST KEY : ");
    print_key(bKey);


    UserPrivateKey usr13PriKey;
    extract_sgx_safe(prvkey, usr13PriKey, "test13@mail.com");

    BroadcastKey decryptedBroadcastKey;
    decrypt_sgx_safe(&decryptedBroadcastKey, cipher, shortPubKey, prvkey,
        usr13PriKey, "test13@mail.com", S, MAX_RECEIVER);
    printf("DECRT KEY : ");
    print_key(decryptedBroadcastKey);
    printf("TOTAL TIME : %f\n", elapsed);

    Decrypt(cipher, pubkey, usr13PriKey, "test13@mail.com", S, MAX_RECEIVER);

    return 0;
}
