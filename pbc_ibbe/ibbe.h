
#include "pbc.h"
#include "pbc_test.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

#define MAX_RECEIVER 10000
#define MAX_STRING_LENGTH 20

typedef struct {
    element_t w, v;
    element_t *h;
} PublicKey;

typedef struct {
    element_t g, r;
} PrivateKey;

typedef element_t IdentityKey;

typedef struct {
    element_t c1, c2, c3;
} Cipher;

typedef element_t Plain;

int Setup(PublicKey *puk, PrivateKey *prk, int argc, char** argv);
int Extract(PrivateKey key, IdentityKey idkey, char* id);
int DestroySK(IdentityKey ikey);
int Encrypt(mpz_t message, Cipher *cipher, PublicKey key, char idSet[][MAX_STRING_LENGTH], int idNum);
int Decrypt(Plain *plain, Cipher cipher, PublicKey key, IdentityKey ikey, char* id, char idSet[][MAX_STRING_LENGTH], int idNum);
