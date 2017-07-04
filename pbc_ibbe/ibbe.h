
#include "pbc.h"
#include "pbc_test.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

#define MAX_RECEIVER 100
#define MAX_STRING_LENGTH 20




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
} Ciphertext;

typedef element_t Plain;

typedef unsigned char BroadcastKey[32];

/* SGX SAFE METHODS - ADMIN USE */
int setup_sgx_safe(PublicKey *puk, ShortPublicKey *spuk, MasterSecretKey *prk,
    int argc, char** argv);

int extract_sgx_safe(MasterSecretKey key, UserPrivateKey idkey, char* id);

int encrypt_sgx_safe(PublicKey key, BroadcastKey* bKey, Ciphertext *cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, char idSet[][MAX_STRING_LENGTH], int idCount);

int decrypt_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount);

/* NON-SGX METHODS - USER USE */
int DestroySK(UserPrivateKey ikey);
int Encrypt(element_t k, Ciphertext *cipher, PublicKey key, char idSet[][MAX_STRING_LENGTH], int idNum);
int Decrypt(Ciphertext cipher, PublicKey key, UserPrivateKey ikey, char* id, char idSet[][MAX_STRING_LENGTH], int idNum);
