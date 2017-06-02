#ifndef BLS_H
#define BLS_H

#include <pbc/pbc.h>


#ifdef __cplusplus
extern "C"{
#endif



/**
Data structures
**/
struct bls_sys_param_s {
    pairing_ptr pairing;
    element_t g;
    int signature_length;
};

typedef struct bls_sys_param_s bls_sys_param_t[1];
typedef struct bls_sys_param_s *bls_sys_param_ptr;

struct bls_private_key_s {
    bls_sys_param_ptr param;
    element_t x;
};
typedef struct bls_private_key_s bls_private_key_t[1];
typedef struct bls_private_key_s *bls_private_key_ptr;

struct bls_public_key_s {
    bls_sys_param_ptr param;
    element_t gx;
};

typedef struct bls_public_key_s bls_public_key_t[1];
typedef struct bls_public_key_s *bls_public_key_ptr;


/**
Functions
**/

void bls_gen_sys_param(bls_sys_param_ptr param, pairing_ptr pairing);
void bls_clear_sys_param(bls_sys_param_ptr param);
void bls_gen(bls_public_key_ptr pk, bls_private_key_ptr sk, bls_sys_param_ptr param);
void bls_clear_public_key(bls_public_key_ptr pk);
void bls_clear_private_key(bls_private_key_ptr sk);
void bls_sign(unsigned char *sig, unsigned int hashlen, unsigned char *hash, bls_private_key_ptr sk);
int bls_verify(unsigned char *sig, unsigned int hashlen, unsigned char *hash,	bls_public_key_ptr pk);

#ifdef __cplusplus
}
#endif

  #endif
