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

/*
  element_t decrypted_key;
  begin = clock();

  Gen_decr_prod_from_indicies(gbs, 2, users_index, users_count, &mykey);
  DecryptKEM_using_product(gbs, &mykey, decrypted_key, generated_ct);

  end = clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("Time generating decryption key: %f\n", time_spent);

  printf("Sym key : \n");
  element_out_str(stdout, 0, decrypted_key);
  printf("\n");

  printf("Broadcast DECRYPTED all the way ... \n ");


*/
}

int broadcast_decrypt_group(
  int* users_index, int users_count,
  unsigned char* user_broadcast_key, int ubk_length,
  unsigned char* cipher, int cipher_length,
  unsigned char* sym_key, int* sym_key_length)
{
  global_broadcast_params_t gbs;
  broadcast_system_t sys;

  char* config_file = broadcast_system_file_name();
  printf("Loading public key and system config : %s\n", config_file);
  LoadParams(config_file, &gbs, &sys);

  // TODO : continue from here
}


void flush_to_bytes(element_t elem, unsigned char* result, int length)
{
  length = element_length_in_bytes(elem);
  result = pbc_malloc(length);
  element_to_bytes(result, elem);
}

int git_test(void);

int main_q(void)
{
//    one_time_init();

  // ENCRYPT
  int n = N;
  int users_index[n];
  for(int i=0; i<n; i++)
    users_index[i] = i + 1;
  char sym_key[32];
  char cipher[512];

  //broadcast_encrypt_group(users_index, n, sym_key, cipher);
  printf("%d\n", strlen(sym_key));
  return 0;



  //one_time_init();

  //char* user_key;
  //generate_user_broadcast_key(2);


  //broadcast_encrypt_group(users_index, 10, sym_key, cipher);

  return 0;
//--------------------------------------------------
  int i;

  global_broadcast_params_t gbs;

  //Global Setup
  Setup_global_broadcast_params(&gbs, N, "d201.param");

  if(0 && DEBUG) {
    printf("\ng = ");
    element_out_str(stdout, 0, gbs->g);
    printf("\nh = ");
    element_out_str(stdout, 0, gbs->h);
    for(i = 0; i < 1; i++) {
      printf("\nThe next element is %d------------------------------------",i);
      printf("\ngs[%d] = ", i);
      element_out_str(stdout, 0, gbs->gs[i]);
      printf("\nhs[%d] = ",i);
      element_out_str(stdout, 0, gbs->hs[i]);
    }
    printf("\n");
  }

  //Broadcast System Setup
  broadcast_system_t sys;
  Gen_broadcast_system(gbs, &sys);

  struct single_priv_key_s mykey;
  struct single_priv_key_s mykey2;
  struct single_priv_key_s mykey3;

  Get_priv_key(gbs, sys, 2, &mykey);
  //if(DEBUG) printf("done 1\n");
  //if(DEBUG) printf("done 2\n");
  Get_priv_key(gbs, sys, 2, &mykey3);
  if(DEBUG) printf("done 3\n");

/*
  if(DEBUG && 0) {
    printf("\ng_i = ");
    element_out_str(stdout, 0, mykey.g_i);
    printf("\nh_i = ");
    element_out_str(stdout, 0, mykey.h_i);
    printf("\ng_i_gamma = ");
    element_out_str(stdout, 0, mykey.g_i_gamma);
    printf("\n");
    printf("\ng_i = ");
    element_out_str(stdout, 0, mykey2.g_i);
    printf("\nh_i = ");
    element_out_str(stdout, 0, mykey2.h_i);
    printf("\ng_i_gamma = ");
    element_out_str(stdout, 0, mykey2.g_i_gamma);
    printf("\n");
     printf("\ng_i = ");
    element_out_str(stdout, 0, mykey3.g_i);
    printf("\nh_i = ");
    element_out_str(stdout, 0, mykey3.h_i);
    printf("\ng_i_gamma = ");
    element_out_str(stdout, 0, mykey3.g_i_gamma);
    printf("\n");
 }
*/
  char recip[N_DIV_EIGHT];
  for(i = 0; i < 2; i++) recip[i] = 254;
  for(i = 2; i < N_DIV_EIGHT; i++) recip[i] = 0;

  Gen_encr_prod_from_bitvec(gbs, sys, recip);
  //Product_Is_Right(gbs, sys, recip);
  //TESTING FOR SYSTEM LOAD AND STORE
  global_broadcast_params_t gbp2;
  broadcast_system_t sys2;
  global_broadcast_params_t gbp3;
  broadcast_system_t sys3;

  StoreParams("system.stor", gbs, sys);
  printf("\ndone storing!!!!!!!!!\n\n");
  LoadParams("system.stor", &gbp2, &sys2);
  LoadParams("system.stor", &gbp3, &sys3);

  printf("\ndone loading!!!!!!!!!\n\n");
  //StoreParams("system2.stor", "pairing2.stor", gbp2, sys2);
  //LoadParams("system2.stor", "pairing2.stor", &gbs, &sys);

  Get_priv_key(gbs, sys, 2, &mykey2);

  if(DEBUG) {
    printf("\noldg = ");
    element_out_str(stdout, 0, gbs->g);
    printf("\nnew = ");
    element_out_str(stdout, 0, gbp2->g);
    printf("\noldh = ");
    element_out_str(stdout, 0, gbs->h);
    printf("\nnew = ");
    element_out_str(stdout, 0, gbp2->h);
    printf("\noldgs = ");
    element_out_str(stdout, 0, gbs->gs[0]);
    printf("\nnew = ");
    element_out_str(stdout, 0, gbp2->gs[0]);
    printf("\nold = ");
    element_out_str(stdout, 0, gbs->gs[31]);
    printf("\nnew = ");
    element_out_str(stdout, 0, gbp2->gs[31]);
    printf("\noldhs = ");
    element_out_str(stdout, 0, gbs->hs[0]);
    printf("\nnew = ");
    element_out_str(stdout, 0, gbp2->hs[0]);
    printf("\nold = ");
    element_out_str(stdout, 0, gbs->hs[31]);
    printf("\nnew = ");
    element_out_str(stdout, 0, gbp2->hs[31]);
    printf("\n old n_u = %d", gbs->num_users);
    printf("\n new n_u = %d", gbp2->num_users);
    printf("\nolde = ");
    element_out_str(stdout, 0, sys->encr_prod);
    printf("\nnew = ");
    element_out_str(stdout, 0, sys2->encr_prod);
    printf("\noldp = ");
    element_out_str(stdout, 0, sys->pub_key);
    printf("\nnew = ");
    element_out_str(stdout, 0, sys2->pub_key);
  }


  //int in_recip[5] = {4, 5, 6, 7, 8 };
  //int num_recip = 5;
  //int rems[3] = { 5, 6, 7 };
  //int N_rems = 3;
  //int adds[12] = { 2, 3, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16 };
  //int N_adds = 12;
  // FINAL ELEMENTS IN PRODUCT SHOULD BE 2-8, & 10-16

  /*
  Gen_encr_prod_from_indicies(gbs, sys2, in_recip, num_recip);

  if(DEBUG) {
    PrintBitString(sys2->recipients,BSL);
    printf("\nsys2 encr_product = ");
    element_out_str(stdout, 0, sys2->encr_prod);
    printf("\n");
  }

  Change_encr_prod_indicies(gbs, sys2, adds, N_adds, rems, N_rems);
  if(DEBUG) {
    PrintBitString(sys2->recipients,BSL);
    printf("\nsys2 encr_product = ");
    element_out_str(stdout, 0, sys2->encr_prod);
    printf("\n");
  }


  if(DEBUG) {
    PrintBitString(sys->recipients,BSL);
    printf("\nsys1 encr_product = ");
    element_out_str(stdout, 0, sys->encr_prod);
  }
  */

  Gen_decr_prod_from_bitvec(gbs, 2, recip, &mykey);
  //if(DEBUG && 0) printf("\ndone 1 decr\n");
  Gen_decr_prod_from_bitvec(gbs, 2, recip, &mykey2);
  //if(DEBUG && 0) printf("\ndone 2 decr\n");
  Gen_decr_prod_from_bitvec(gbs, 2, recip, &mykey3);
  //if(DEBUG && 0) printf("\ndone 3 decr\n");
  //Gen_decr_prod_from_indicies(gbs, 2, in_recip, num_recip, &mykey2);
  //Change_decr_prod_indicies(gbs, 2, adds, N_adds, rems, N_rems, &mykey2);

  //Gen_decr_prod_from_bitvec(gbs, 2, recip, &mykey3);


  if(0 && DEBUG) {
    printf("\n");
    printf("mykey1 decr_product = ");
    element_out_str(stdout, 0, mykey.decr_prod);
    printf("\n");
  }
  if(DEBUG && 0) {
    printf("\n");
    printf("mykey2 decr_product = ");
    element_out_str(stdout, 0, mykey2.decr_prod);
    printf("\n");
  }
  if(DEBUG && 0) {
    printf("\n");
    printf("mykey3 decr_product = ");
    element_out_str(stdout, 0, mykey3.decr_prod);
    printf("\n");
  }




  //TESTING FOR SINGLE KEY LOAD AND STORE
  priv_key_t load_key = (priv_key_t)pbc_malloc(sizeof(struct single_priv_key_s));

  StorePrivKey("key2.stor", &mykey);
  LoadPrivKey("key2.stor", &load_key, gbs);

  if(DEBUG) {
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.g_i_gamma);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->g_i_gamma);
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.g_i);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->g_i);
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.h_i);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->h_i);
    printf("\nold = ");
    element_out_str(stdout, 0, mykey.decr_prod);
    printf("\nnew = ");
    element_out_str(stdout, 0, load_key->decr_prod);
    printf("\n index = %d", mykey.index);
    printf("\n index = %d", load_key->index);
  }

  ct_t myCT = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  ct_t myCT2 = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  ct_t myCT3 = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  //int recip2[14] = { 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16 };
  //int n_recip2 = 14;
  element_t key1;
  element_t key2;
  element_t key3;
  element_t key4;
  element_t key5;
  element_t key6;

  BroadcastKEM_using_product(gbs, sys, myCT, key1);
  DecryptKEM_using_product(gbs, &mykey, key4, myCT);
  BroadcastKEM_using_product(gbs, sys, myCT3, key3);
  DecryptKEM_using_product(gbp3, &mykey3, key6, myCT3);
  BroadcastKEM_using_product(gbs, sys, myCT2, key2);
  DecryptKEM_using_product(gbp2, &mykey2, key5, myCT2);


  //BroadcastKEM_using_bitvec(gbs, sys, recip, myCT2, key2);
  //BroadcastKEM_using_indicies(gbs, sys, myCT3, recip2, n_recip2, key3);


  if(DEBUG) {
    //COMPARE ALL THREE CTs!
    printf("\n1-C0 = ");
    element_out_str(stdout, 0, myCT->C0);
    printf("\n2-C0 = ");
    element_out_str(stdout, 0, myCT2->C0);
    printf("\n3-C0 = ");
    element_out_str(stdout, 0, myCT3->C0);
    printf("\n1-C1 = ");
    element_out_str(stdout, 0, myCT->C1);
    printf("\n2-C1 = ");
    element_out_str(stdout, 0, myCT2->C1);
    printf("\n3-C1 = ");
    element_out_str(stdout, 0, myCT3->C1);
  }


  printf("\nkey1 = ");
  element_out_str(stdout, 0, key1);
  printf("\n");
  printf("\nkey2 = ");
  element_out_str(stdout, 0, key2);
  printf("\n");
  printf("\nkey3 = ");
  element_out_str(stdout, 0, key3);
  printf("\n");

  //PrintBitString(mykey.recipients, BSL);
  //DecryptKEM_using_product(gbs, &mykey2, key5, myCT2);


  //printf("\nmyprivkey = ");
  //element_out_str(stdout, 0, mykey.g_i_gamma);
  //printf("\n");
  printf("\nkey1 = ");
  element_out_str(stdout, 0, key4);
  printf("\n");
  printf("\nkey2 = ");
  element_out_str(stdout, 0, key5);
  printf("\n");
  printf("\nkey3 = ");
  element_out_str(stdout, 0, key6);
  printf("\n");

  FreeCT(myCT);
  FreeBCS(sys);
  FreeGBP(gbs);
  FreeGBP(gbp2);
  FreeBCS(sys2);
  FreePK(&mykey);
  return 0;

}

void print_sys_info(global_broadcast_params_t gbs, broadcast_system_t sys)
{
    printf("Global Broadcast Params: \n");
    element_out_str(stdout, 0, gbs->g); printf("\n");
    element_out_str(stdout, 0, gbs->h); printf("\n");
    printf("%d\n", gbs->num_users);

    printf("Broadcast System: \n");
    //element_out_str(stdout, 0, sys->encr_prod); printf("\n");
    element_out_str(stdout, 0, sys->pub_key); printf("\n");
    element_out_str(stdout, 0, sys->priv_key); printf("\n");
}

int git_test(void)
{
  int i;


  // SETUP
  global_broadcast_params_t gbs_src;
  //Setup_global_broadcast_params(&gbs, N, "a.param");
  Setup_global_broadcast_params(&gbs_src, N, "d201.param");
  broadcast_system_t sys_src;
  Gen_broadcast_system(gbs_src, &sys_src);
  print_sys_info(gbs_src, sys_src);

  // pri key
  struct single_priv_key_s mykey;
  Get_priv_key(gbs_src, sys_src, 1, &mykey);


  StoreParams("stefan.temp", gbs_src, sys_src);
  global_broadcast_params_t gbs;
  broadcast_system_t sys;
  LoadParams("stefan.temp", &gbs, &sys);
  //element_set(sys->priv_key, sys_src->priv_key);
  print_sys_info(gbs, sys);

  //return 0;

/*
    //one_time_init();

    global_broadcast_params_t gbs;
    broadcast_system_t sys;

    char* config_file = broadcast_system_file_name();
    printf("Loading public key and system config : %s\n", config_file);
    LoadParams(config_file, &gbs, &sys);
    print_sys_info(gbs, sys);
    return 0;
*/



  // ENCRYPT
  int n = 10;
  int users_index[n];
  for(int i=0; i<n; i++)
    users_index[i] = i + 1;
  Gen_encr_prod_from_indicies(gbs, sys, users_index, n);
  ct_t myCT = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t key1;
  BroadcastKEM_using_product(gbs, sys, myCT, key1);

  // DECRYPT
  element_t key2;
  Gen_decr_prod_from_indicies(gbs, 1, users_index, n, &mykey);
  DecryptKEM_using_product(gbs, &mykey, key2, myCT);

  printf("\nkey1 = ");
  element_out_str(stdout, 0, key1);
  printf("\n");
  printf("\nkey2 = ");
  element_out_str(stdout, 0, key2);


  FreeCT(myCT);
  FreeBCS(sys);
  FreeGBP(gbs);
  FreePK(&mykey);
  //FreePK(&mykey2);
  return 0;
}
