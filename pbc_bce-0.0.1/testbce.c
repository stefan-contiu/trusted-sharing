/*
   Implementation of Boneh-Gentry-Waters broadcast encryption scheme
   Original code by:
      Matt Steiner   MattS@cs.stanford.edu
      Stefan Contiu  stefan.contiu@bordeaux.fr
   testbce.c
*/

/*
  TODO :
  [ ] byte serialization for ciphertext
  [ ] byte de-serialization for ciphertext
  [ ] sha256 for encryption
  [ ] sha256 for decryption
  [ ] byte serialization for user_broadcast_key
  [ ] byte de-serialization for user_broadcast_key
  [ ] call the C methods from Python
*/


#include <string.h>
#include "pbc_bce.h"
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

#define N (100000)
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

int one_time_init()
{
  global_broadcast_params_t gbs;
  Setup_global_broadcast_params(&gbs, N, "d201.param");

  broadcast_system_t sys;
  Gen_broadcast_system(gbs, &sys);

  char* config_file = broadcast_system_file_name();
  printf("Saving public key and system config : %s\n", config_file);
  StoreParams(config_file, gbs, sys);

  FreeGBP(gbs);
  // TODO : fix the method to skip freeing the encrypted product
  //FreeBCS(sys);
  return 0;
}

int generate_user_broadcast_key(int user_index)
{
  global_broadcast_params_t gbs;
  broadcast_system_t sys;

  char* config_file = broadcast_system_file_name();
  printf("Loading public key and system config : %s\n", config_file);
  LoadParams(config_file, &gbs, &sys);

  struct single_priv_key_s mykey;
  Get_priv_key(gbs, sys, user_index, &mykey);

  char* s = itoa(user_index, 10);
  StorePrivKey(concat(concat("user_", s), ".key"), &mykey);

  printf("Private key saved to file for user : %d\n", user_index);

  FreeGBP(gbs);
  return 0;
}

int broadcast_encrypt_group(int* users_index, int users_count,
      char* sym_key, char* cipher)
{
  global_broadcast_params_t gbs;
  broadcast_system_t sys;

  char* config_file = broadcast_system_file_name();
  printf("Loading public key and system config : %s\n", config_file);
  LoadParams(config_file, &gbs, &sys);

  ct_t generated_ct = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t generated_key;

  clock_t begin = clock();

  BroadcastKEM_using_indicies(gbs, sys, generated_ct,
      users_index, users_count, generated_key);

  clock_t end = clock();
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("Time generating encryption key: %f\n", time_spent);

  int generated_key_length = element_length_in_bytes(generated_key);
  unsigned char* result = pbc_malloc(generated_key_length);
  element_to_bytes(result, generated_key);

  int cipher_length = element_length_in_bytes(generated_ct->C1);
  printf("Cipher length bytes : %d\n", cipher_length);



  // benchmarks only ------------------
  struct single_priv_key_s mykey;
  Get_priv_key(gbs, sys, 2, &mykey);

  element_t decrypted_key;
  begin = clock();
  Decrypt_BC_KEM_using_indicies(gbs, &mykey, decrypted_key, generated_ct,
    users_index, users_count);
  end = clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("Time generating decryption key: %f\n", time_spent);

  printf("Broadcast DECRYPTED all the way ... \n ");



  // TODO : ...
  //sym_key = hash()
  // persist the key
}

int broadcast_decrypt_group(
  const int* users_index, int users_count,
  const unsigned char* user_broadcast_key,
  const unsigned char* cipher,
  unsigned char* sym_key)
{
  global_broadcast_params_t gbs;
  broadcast_system_t sys;

  char* config_file = broadcast_system_file_name();
  printf("Loading public key and system config : %s\n", config_file);
  LoadParams(config_file, &gbs, &sys);

  // TODO : continue from here
}

/*
void flush_to_bytes(element_t elem, unsigned char* result, int length)
{
  length = element_length_in_bytes(elem);
  result = pbc_malloc(length);
  element_to_bytes(result, elem);
}
*/

int bvt()
{
  // global params
  global_broadcast_params_t gbs;
  Setup_global_broadcast_params(&gbs, N, "d201.param");
  printf("Loaded broadcast system global params ... \n ");

  // setup
  broadcast_system_t sys;
  Gen_broadcast_system(gbs, &sys);
  //printf("Size of global broadcast params : %d\n", sizeof(gbs));
  //printf("Size of broadcast system : %d\n", sizeof(sys));

  // private keys ----------------------------------
  struct single_priv_key_s mykey;
  struct single_priv_key_s mykey2;
  struct single_priv_key_s mykey3;

  char recip[N_DIV_EIGHT];
  Get_priv_key(gbs, sys, 1, &mykey);
  Gen_decr_prod_from_bitvec(gbs, 1, recip, &mykey);
  StorePrivKey("k_alice.be", &mykey);

  Get_priv_key(gbs, sys, 2, &mykey2);
  Get_priv_key(gbs, sys, 3, &mykey3);
  printf("Generated 3 Private Keys ... \n ");
  // this is not generating the decr_prod which is required
  // for saving/loading the private keys
  // TODO : modify save/load of private key to be independent of the
  //decr_prod
  //StorePrivKey("k_alice.be", &mykey);
  //StorePrivKey("k_bob.be", mykey2);
  //StorePrivKey("k_steve.be", mykey3);
  // use LoadPrivKey

  // receipents (group members)
  // TODO : write a method that will mark bits per memebrs
  int i;
  for(i = 0; i < 2; i++) recip[i] = 254;
  for(i = 2; i < N_DIV_EIGHT; i++) recip[i] = 0;
  Gen_encr_prod_from_bitvec(gbs, sys, recip);
  printf("Encoded the receipients in bit vector ... \n ");



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
  printf("Broadcast ENCRYPTED motherfucker ... \n ");
  //printf("Size of cipher : %d\n", element_length_in_bytes(myCT));
  printf("Size of key : %d\n", element_length_in_bytes(key1));

//  printf("\nsym_key = ");

  //element_out_str(stdout, 0, key1);


  DecryptKEM_using_product(gbs, &mykey, key4, myCT);
  printf("Broadcast DECRYPTED motherfucker ... \n ");

  StoreParams("system.stor", gbs, sys);
  return 0;
}

int main(void)
{
  // INIT

  clock_t begin = clock();
  one_time_init();
  clock_t end = clock();
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("Time generating public key: %f\n", time_spent);
  return 0;





  // ENCRYPT
  int users_index[N];
  for(int i=0; i<N; i++)
    users_index[i] = i + 1;
  char sym_key[32];
  char cipher[512];

  broadcast_encrypt_group(users_index, N, sym_key, cipher);

  return 0;



  //one_time_init();

  //char* user_key;
  //generate_user_broadcast_key(2);


  broadcast_encrypt_group(users_index, 10, sym_key, cipher);

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
