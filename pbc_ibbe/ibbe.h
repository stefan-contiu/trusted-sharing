
#ifndef IBBE_H
#define IBBE_H

#include "pbc.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

//#if defined (__cplusplus)
//extern "C" {
//#endif

// NOTE : if the curve changes, the size will change mostlikely
#define PAIRING_ELEMENT_SIZE 128
#define ZN_ELEMENT_SIZE 20

#define MAX_STRING_LENGTH 20
#define THREADS_COUNT 8

typedef struct {
    element_t w, v;
    element_t *h;
    int h_size;
} PublicKey;

typedef struct {
    element_t w, v, h;
} ShortPublicKey;

typedef struct {
    element_t g, gamma;
} MasterSecretKey;

typedef element_t UserPrivateKey;

typedef struct {
    element_t c1, c2;
    element_t h_pow_product_gamma_hash;
} Ciphertext;

typedef element_t Plain;

typedef unsigned char BroadcastKey[32];

typedef unsigned char GroupKey[32];

typedef unsigned char GroupKeyEncryptedByPartitionKey[48]; // 32 for the key, 16 for IV

typedef struct {
    unsigned char encryptedKey[32];
    unsigned char iv[16];
} EncryptedGroupKey;


/* SGX SAFE METHODS - FOR ADMIN USE */
int setup_sgx_safe(PublicKey *puk, ShortPublicKey *spuk, MasterSecretKey *prk,
    int max_group_size, int argc, char** argv);

int extract_sgx_safe(MasterSecretKey key, UserPrivateKey idkey, char* id);

int encrypt_sgx_safe(BroadcastKey* bKey, Ciphertext *cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, char idSet[][MAX_STRING_LENGTH], int idCount);

int add_user_sgx_safe(Ciphertext *cipher, MasterSecretKey msk, char* id);

int rekey_user_sgx_safe(BroadcastKey* bKey, Ciphertext *cipher, ShortPublicKey spk, MasterSecretKey msk);

int decrypt_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk,
    char idSet[][MAX_STRING_LENGTH], int idCount);

int decrypt_with_key_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount);

/* NON-SGX METHODS - FOR USER USE */
int decrypt_user(BroadcastKey* bKey,
    Ciphertext cipher, PublicKey key, UserPrivateKey ikey,
    const char* id, char idSet[][MAX_STRING_LENGTH], int idCount);

int decrypt_user_no_optimizations(BroadcastKey* bKey,
    Ciphertext cipher, PublicKey key, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount);

static inline void print_hex(unsigned char *h, int l)
{
    for (int i=0; i<l; i++)
        printf("%02X", h[i]);
    printf("\n");
}

/* SERIALIZATION & DE-SERIALIZATION ---------------------------------  */
/* TODO : it's not decided weather this should stay in the enclave or not */
void serialize_public_key(PublicKey pk, unsigned char* s, int* s_count);
void serialize_short_public_key(ShortPublicKey spk, unsigned char* s, int* s_count);
void serialize_master_secret_key(MasterSecretKey msk, unsigned char* s, int* s_count);
void serialize_cipher(Ciphertext c, unsigned char* s, int* s_count);

void deserialize_public_key(unsigned char s[], PublicKey* pk);
void deserialize_short_public_key(unsigned char s[], ShortPublicKey* spk);
void deserialize_master_secret_key(unsigned char s[], MasterSecretKey* msk);
void deserialize_cipher(unsigned char s[], Ciphertext* c);
/* ------- */


/* SP-IBBE operations */
/*
int enclave_create_group(
    GroupKeyEncryptedByPartitionKey gpKeys[], Ciphertext gpCiphers[],
    ShortPublicKey pubKey, MasterSecretKey msk,
    char **idSet, int idCount, int partitionCount);

int user_decrypt_group_key(
    GroupKey* gkey,
    GroupKeyEncryptedByPartitionKey partEncKey, Ciphertext partCipher,
    PublicKey key, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount);

int enclave_add_user_to_group(
    Ciphertext partCipher[],
    char* id, char** idSet, int* idCount, int* partitionCount
);

int enclave_remove_user_from_group(

);
*/
unsigned char* gen_random_bytestream(int n);


//#if defined (__cplusplus)
//}
//#endif

#endif
