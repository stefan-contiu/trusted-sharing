#ifndef BBS_H
#define BBS_H

#include <pbc/pbc.h>


#ifdef __cplusplus
extern "C"{
#endif



struct bbs_sys_param_s {
    pairing_ptr pairing;
    int signature_length;
};
typedef struct bbs_sys_param_s bbs_sys_param_t[1];
typedef struct bbs_sys_param_s *bbs_sys_param_ptr;

struct bbs_group_public_key_s {
    bbs_sys_param_ptr param;
    element_t g1, g2;
    element_t h, u, v, w;
    /* and precomputed values */
    element_t pr_g1_g2;
    element_t pr_h_g2;
    element_t pr_h_w;
    element_t pr_g1_g2_inv;
};
typedef struct bbs_group_public_key_s bbs_group_public_key_t[1];
typedef struct bbs_group_public_key_s *bbs_group_public_key_ptr;

struct bbs_group_private_key_s {
    bbs_sys_param_ptr param;
    element_t A;
    element_t x;
    /* and precomputed values */
    element_t pr_A_g2;
};
typedef struct bbs_group_private_key_s bbs_group_private_key_t[1];
typedef struct bbs_group_private_key_s *bbs_group_private_key_ptr;

struct bbs_manager_private_key_s {
    bbs_sys_param_ptr param;
    element_t xi1, xi2;
};

typedef struct bbs_manager_private_key_s bbs_manager_private_key_t[1];
typedef struct bbs_manager_private_key_s *bbs_manager_private_key_ptr;

void bbs_gen_sys_param(bbs_sys_param_ptr param, pairing_ptr pairing);
void bbs_gen(bbs_group_public_key_ptr gpk, bbs_manager_private_key_ptr gmsk, int n, bbs_group_private_key_t *gsk, bbs_sys_param_ptr param);
void bbs_sign(unsigned char *sig,	int hashlen, void *hash, bbs_group_public_key_ptr gpk, bbs_group_private_key_ptr gsk);
int bbs_verify(unsigned char *sig, int hashlen, void *hash, bbs_group_public_key_ptr gpk);
int bbs_open(element_ptr A, bbs_group_public_key_ptr gpk, bbs_manager_private_key_ptr gmsk, int hashlen, void *hash, unsigned char *sig);


void bbs_free_gpk(bbs_group_public_key_ptr gpk);
void bbs_free_gsk(bbs_group_private_key_t *gsk, int n);
void bbs_free_gmsk(bbs_manager_private_key_ptr gmsk);

#ifdef __cplusplus
}
#endif

#endif
