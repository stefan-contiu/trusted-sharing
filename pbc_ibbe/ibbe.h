
#ifndef IBBE_H
#define IBBE_H

#include "pbc.h"
#include "pbc_test.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

#define MAX_STRING_LENGTH 20
#define THREADS_COUNT 8

typedef struct {
    element_t w, v;
    element_t *h;
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

typedef unsigned char GroupKeyEncryptedByPartitionKey[32];

/* SGX SAFE METHODS - FOR ADMIN USE */
int setup_sgx_safe(PublicKey *puk, ShortPublicKey *spuk, MasterSecretKey *prk,
    int max_group_size, int argc, char** argv);

int extract_sgx_safe(MasterSecretKey key, UserPrivateKey idkey, char* id);

int encrypt_sgx_safe(BroadcastKey* bKey, Ciphertext *cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, char idSet[][MAX_STRING_LENGTH], int idCount);

int add_user_sgx_safe(Ciphertext *cipher, MasterSecretKey msk, char* id);

int decrypt_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk,
    char idSet[][MAX_STRING_LENGTH], int idCount);

int decrypt_with_key_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount);

/* NON-SGX METHODS - FOR USER USE */
int decrypt_user(BroadcastKey* bKey,
    Ciphertext cipher, PublicKey key, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount);

int decrypt_user_no_optimizations(BroadcastKey* bKey,
    Ciphertext cipher, PublicKey key, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount);


#endif
