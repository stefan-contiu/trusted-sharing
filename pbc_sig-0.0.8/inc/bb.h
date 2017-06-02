#ifndef BB_H
#define BB_H

#include <pbc/pbc.h>


#ifdef __cplusplus
extern "C"{
#endif



struct bb_sys_param_s {
    pairing_ptr pairing;
    int signature_length;
};
typedef struct bb_sys_param_s bb_sys_param_t[1];
typedef struct bb_sys_param_s *bb_sys_param_ptr;

struct bb_private_key_s {
    bb_sys_param_ptr param;
    element_t x, y;
};
typedef struct bb_private_key_s bb_private_key_t[1];
typedef struct bb_private_key_s *bb_private_key_ptr;

struct bb_public_key_s {
    bb_sys_param_ptr param;
    element_t g1, g2, u, v, z;
};
typedef struct bb_public_key_s bb_public_key_t[1];
typedef struct bb_public_key_s *bb_public_key_ptr;

void bb_gen_sys_param(bb_sys_param_ptr param, pairing_ptr pairing);
void bb_gen(bb_public_key_ptr pk, bb_private_key_ptr sk, bb_sys_param_ptr param);
void bb_sign(unsigned char *sig, unsigned int hashlen, unsigned char *hash,	bb_public_key_ptr pk, bb_private_key_ptr sk);
int bb_verify(unsigned char *sig, unsigned int hashlen, unsigned char *hash, bb_public_key_ptr pk);

void bb_free_sk(bb_private_key_t sk);
void bb_free_pk(bb_public_key_t pk);

#ifdef __cplusplus
}
#endif

#endif
