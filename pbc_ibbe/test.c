#include "ibbe.h"
#include "spibbe.h"
#include <stdio.h>
#include <time.h>
#include <string>

void print_key(unsigned char *h)
{
    print_hex(h, 32);
}

/*
 *  Basic Validation Test for IBBE operations.
 */
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

/*
int bvt_spibbe(int argc, char** argv, int group_size, int partition_max_size)
{
    char **S;
    if (( S = (char **) malloc( group_size * sizeof( char* ))) == NULL )
    {
        printf("ERROR ALLOC list\n");
    }
//    for (int i = 0; i < group_size; i++ )
//    {
//      if (( S[i] = malloc(MAX_STRING_LENGTH)) == NULL )
//      { printf("ERROR ALLOC item\n"); }
//    }

    //char S[group_size][MAX_STRING_LENGTH];
    //printf("users allocated !\n");

    int i;
    clock_t time1, time2;
    for (i = 0; i < group_size; i++)
    {
        S[i] = (char*) malloc(MAX_STRING_LENGTH);
        sprintf(S[i], "test%d@mail.com\0", i+1);
        //printf("SRC : %s\n", S[i]);
    }
    //printf("users generated !\n");

    PublicKey pubkey;
    MasterSecretKey prvkey;
    ShortPublicKey shortPubKey;

    setup_sgx_safe(&pubkey, &shortPubKey, &prvkey,
        partition_max_size + 1, argc, argv);
    //printf("System set-up : DONE\n");

    struct timespec start, finish;
    double elapsed;

    int partitions_count = group_size / partition_max_size;
    GroupKeyEncryptedByPartitionKey pKeys[partitions_count];
    Ciphertext pCiphers[partitions_count];

    //printf("Partitions to be constructed : %d ...\n", partitions_count);

    clock_gettime(CLOCK_MONOTONIC, &start);
    enclave_create_group(pKeys, pCiphers, shortPubKey, prvkey, S, group_size, partition_max_size);
    clock_gettime(CLOCK_MONOTONIC, &finish);

    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
    // TODO : uncomment this for group metrics
    //printf("Create group took : %f s\n", elapsed);

    // ------ extract a key and validate group
    UserPrivateKey usr13PriKey;
    extract_sgx_safe(prvkey, usr13PriKey, "test13@mail.com");

    int pStart = 0;
    int pEnd   = partition_max_size;
    char idPartition[partition_max_size][MAX_STRING_LENGTH];
    for (int i=pStart; i<pEnd; i++)
    {
        memcpy(idPartition[i - pStart], S[i], MAX_STRING_LENGTH);
    }

    //printf("Decryption partition constructed... \n");

    GroupKey groupKey;
    clock_gettime(CLOCK_MONOTONIC, &start);
    user_decrypt_group_key(&groupKey,
        pKeys[0], pCiphers[0],
        pubkey, usr13PriKey,
        "test13@mail.com", idPartition, partition_max_size);
    clock_gettime(CLOCK_MONOTONIC, &finish);

    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
    //printf("Decrypt : %f s\n", elapsed);
    printf("%d,%f\n", partition_max_size, elapsed);

    //printf("DEC GRP KEY : ");
    //print_hex(groupKey, 32);

    return 0;
}
*/

void bvt_serialization(int argc, char** argv)
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

    unsigned char* s_pk;
    int pk_size;
    serialize_public_key(pubkey, s_pk, &pk_size);

    unsigned char* s_spk;
    int spk_size;
    serialize_short_public_key(shortPubKey, s_spk, &spk_size);

    unsigned char* s_msk;
    int msk_size;
    serialize_master_secret_key(prvkey, s_msk, &msk_size);
}

/*
int complete_spibbe(int argc, char** argv)
{
    int g_size[8] = {500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000};
    int p_size[5] = {500, 1000, 2500, 5000, 10000};

    //bvt_spibbe(argc, argv, 1000000, 2500);
    //return;

    for(int g=0; g<8; g++)
    {
        int p = 1;
        printf("BENCH CREATE GROUP %d\n", g_size[g]);
        if (g_size[g] >= p_size[p])
            bvt_spibbe(argc, argv, g_size[g], p_size[p]);
    }
}
*/

void bvt_cpp(int argc, char** argv, int g_size, int p_size)
{
    // system set-up
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    setup_sgx_safe(&pubKey, &shortPubKey, &msk,
        p_size, argc, argv);

    // mock a list of members
    std::vector<std::string> members;
    for (int i = 0; i < g_size; i++)
    {
        char* ss = (char*) malloc(MAX_STRING_LENGTH);
        sprintf(ss, "test%d@mail.com", i);
        std::string s(ss);
        members.push_back(s);
    }
    printf("Members generated : %d\n", members.size());

    // create group
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    sp_ibbe_create_group(
        gpKeys, gpCiphers,
        shortPubKey, msk,
        members,
        p_size);

    // extract a key and validate group
    std::string decrypt_user_name = "test930@mail.com";
    UserPrivateKey usr13PriKey;
    extract_sgx_safe(msk, usr13PriKey, (char*) decrypt_user_name.c_str());

    GroupKey groupKey;
    sp_ibbe_user_decrypt(
        &groupKey,
        gpKeys,
        gpCiphers,
        pubKey,
        usr13PriKey,
        decrypt_user_name,
        members,
        p_size);
    return;

    // revoke a user from a middle partition
    sp_ibbe_remove_user(
        shortPubKey,
        msk,
        gpKeys,
        gpCiphers,
        members,
        decrypt_user_name,
        p_size
    );
}


int main(int argc, char** argv)
{
    //bvt_ibbe(argc, argv);
    //bvt_spibbe(argc, argv);
    //bvt_serialization(argc, argv);

    //complete_spibbe(argc, argv);

    //simple_bvt(argc, argv);

    bvt_cpp(argc, argv, 980, 100);
    return 0;
}
