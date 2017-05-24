/*
   Implementation of Boneh-Gentry-Waters broadcast encryption scheme
   Original code by:
      Matt Steiner   MattS@cs.stanford.edu
      Stefan Contiu  stefan.contiu@bordeaux.fr
   testbce.c
*/

/*
  TODO :
  [x] byte serialization for ciphertext
  [ ] byte de-serialization for ciphertext
  [x] byte serialization for user_broadcast_key
  [ ] byte de-serialization for user_broadcast_key
  [x] call the C methods from Python
*/


#include <string.h>
#include "pbc_bce.h"
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define N (32)
#define N_DIV_EIGHT  N/8

char* concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

char* itoa(int val, int base)
{
	static char buf[32] = {0};
	int i = 30;
	for(; val && i ; --i, val /= base)
		buf[i] = "0123456789abcdef"[val % base];
	return &buf[i+1];
}

char* broadcast_system_file_name()
{
    char* s = itoa(N, 10);
    return concat(concat("system_", s), ".config");
}

int save_private_keys(global_broadcast_params_t gbs, broadcast_system_t sys)
{
    char* s = itoa(N, 10);
    char* dirName = concat("keys_", s);

    struct stat st = {0};
    if (stat(dirName, &st) == -1) {
        mkdir(dirName, 0700);
    }

    for(int user_index=1; user_index<=N; user_index++)
    {
        struct single_priv_key_s mykey;
        Get_priv_key(gbs, sys, user_index, &mykey);

        char* fileName = concat(concat("/user_", itoa(user_index, 10)), ".key");
        char* fullFileName = concat(dirName, fileName);
        StorePrivKey(fullFileName, &mykey);
    }

    return 0;
}

int one_time_init()
{
  global_broadcast_params_t gbs;
  Setup_global_broadcast_params(&gbs, N, "d201.param");

  broadcast_system_t sys;
  Gen_broadcast_system(gbs, &sys);

  printf("Saving private keys ... \n");
  save_private_keys(gbs, sys);

  char* config_file = broadcast_system_file_name();
  printf("Saving public key and system config : %s\n", config_file);
  StoreParams(config_file, gbs, sys);


  FreeGBP(gbs);
  // TODO : fix the method to skip freeing the encrypted product
  //FreeBCS(sys);
  return 0;
}

int broadcast_encrypt_group(
    int* users_index, int users_count,
    unsigned char* sym_key, int* sym_key_length,
    char* cipher, int* cipher_length)
{
  global_broadcast_params_t gbs;
  broadcast_system_t sys;
  char* config_file = broadcast_system_file_name();
  LoadParams(config_file, &gbs, &sys);

  ct_t generated_ct = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t generated_key;

  Gen_encr_prod_from_indicies(gbs, sys, users_index, users_count);
  BroadcastKEM_using_product(gbs, sys, generated_ct, generated_key);

  int generated_key_length = element_length_in_bytes(generated_key);
  element_to_bytes(sym_key, generated_key);
  (*sym_key_length) = generated_key_length;

  size_t size;
  char *bp;
  FILE* stream = open_memstream(&bp, &size);
  out(generated_ct->C0, stream);
  out(generated_ct->C1, stream);
  fclose(stream);
  (*cipher_length) = (int)size;
  memcpy(cipher, bp, size);
}

int broadcast_decrypt_group(
  int* users_index, int users_count,
  char* user_private_key_file,
  unsigned char* cipher, int cipher_length,
  unsigned char* sym_key, int* sym_key_length)
{
    // set up the system
    global_broadcast_params_t gbs;
    broadcast_system_t sys;
    char* config_file = broadcast_system_file_name();
    printf("Loading public key and system config : %s\n", config_file);
    LoadParams(config_file, &gbs, &sys);

    // load user private key
    priv_key_t pri_key = (priv_key_t)pbc_malloc(sizeof(struct single_priv_key_s));
    LoadPrivKey(user_private_key_file, &pri_key, gbs);

    // de-serialize the ciphertext
    ct_t deserialized_cipher = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
    element_init(deserialized_cipher->C0, gbs->pairing->G2);
    element_init(deserialized_cipher->C1, gbs->pairing->G1);
    // TODO : is this code valid for reading from a stream?
    FILE* stream = open_memstream(&cipher, &cipher_length);
    in(deserialized_cipher->C0, stream);
    in(deserialized_cipher->C1, stream);
    fclose(stream);

    // decrypt the symmetric key
    element_t decrypted_key;
    Gen_decr_prod_from_indicies(gbs, pri_key->index, users_index, users_count, &pri_key);
    DecryptKEM_using_product(gbs, &pri_key, decrypted_key, deserialized_cipher);

    // serialize the key for the upper level
    int decrypted_key_length = element_length_in_bytes(decrypted_key);
    element_to_bytes(sym_key, decrypted_key);
    (*sym_key_length) = decrypted_key_length;
}


void flush_to_bytes(element_t elem, unsigned char* result, int length)
{
  length = element_length_in_bytes(elem);
  result = pbc_malloc(length);
  element_to_bytes(result, elem);
}

/*
int free_all(void)
{
    FreeCT(myCT);
    FreeBCS(sys);
    FreeGBP(gbs);
    FreePK(&mykey);
    //FreePK(&mykey2);
    return 0;
}
*/
