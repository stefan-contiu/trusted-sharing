/*
 *  TODO : The random and encryption methods need to by replaced with the
 *          SGX correspondents !!!
 */

#include "ibbe.h"
#include "spibbe.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

unsigned char* gen_random_bytestream(int n)
{
    unsigned char* stream=malloc(n + 1);
    size_t i;
    for (i = 0; i < n; i++)
    {
        stream[i] = (unsigned char) (rand() % 255 + 1);
    }
    stream[n] = 0;
    return stream;
}

/*
int create_group(
    GroupKeyEncryptedByPartitionKey** gpKeys, Ciphertext** gpCiphers,
    ShortPublicKey pubKey, MasterSecretKeyCipher mskCipher,
    char idSet[][MAX_STRING_LENGTH], int idCount, int partitionCount)
{
    // decrypt the master secret key (system) by the enclave key
    MasterSecretKey msk;

    //
    create_group_sgx_safe(gpKeys, gpCiphers, pubKey, msk,
        idSet, idCount, partitionCount);
}
*/

int create_group(
    GroupKeyEncryptedByPartitionKey** gpKeys, Ciphertext** gpCiphers,
    ShortPublicKey pubKey, MasterSecretKey msk,
    char idSet[][MAX_STRING_LENGTH], int idCount, int partitionCount)
{
    // generate a random group key
    unsigned char* group_key = gen_random_bytestream(32);

    // split idSet into partitions
    for (int p = 0; p * partitionCount < idCount; p++)
    {
        int pStart = p * partitionCount;
        int pEnd   = pStart + partitionCount;
//        printf("Partition from %d to %d ... \n", pStart, pEnd - 1);
        char idPartition[partitionCount][MAX_STRING_LENGTH];
        for (int i=pStart; i<pEnd; i++)
        {
            memcpy(&idPartition[i - pStart], &idSet[i], MAX_STRING_LENGTH);
        }

        // get a broadcast and ciphertext for the partition
        BroadcastKey bKey;
        Ciphertext bCipher;
        encrypt_sgx_safe(&bKey, &bCipher, pubKey, msk, idPartition, partitionCount);

        // encrypt the group key by the broadcast key
        unsigned char* iv = gen_random_bytestream(16);
        unsigned char encryptedKey[48];
        int len;
        int ciphertext_len;
        EVP_CIPHER_CTX *ctx;
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx,  EVP_aes_256_cbc(), NULL, bKey, iv);
        EVP_EncryptUpdate(ctx, encryptedKey, &len, group_key, sizeof(group_key));
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, encryptedKey + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        // put the partition (encrytped key + iv) and ciphertext to return collections
        // gpKeys[p] = encryptedKey;
        // gpCiphers[p] = bCipher;
    }

    // clean-up if necessary
}
