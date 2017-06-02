#ifndef vlr_H
#define vlr_H

#include <pbc/pbc.h>


#ifdef __cplusplus
extern "C"{
#endif

#include <string.h>


struct vlr_sys_param_s {
    pairing_ptr pairing;
    int signature_length;
};
typedef struct vlr_sys_param_s vlr_sys_param_t[1];
typedef struct vlr_sys_param_s *vlr_sys_param_ptr;

struct vlr_group_public_key_s {
    vlr_sys_param_ptr param;
    element_t g1, g2;
    element_t omega;
};

typedef struct vlr_group_public_key_s vlr_group_public_key_t[1];
typedef struct vlr_group_public_key_s *vlr_group_public_key_ptr;

struct vlr_user_private_key_s {
    vlr_sys_param_ptr param;
    element_t A;
    element_t x;
};
typedef struct vlr_user_private_key_s vlr_user_private_key_t[1];
typedef struct vlr_user_private_key_s *vlr_user_private_key_ptr;

struct vlr_group_revocation_token_s {
    vlr_sys_param_ptr param;
    element_t A;
};

typedef struct vlr_group_revocation_token_s vlr_group_revocation_token_t[1];
typedef struct vlr_group_revocation_token_s *vlr_group_revocation_token_ptr;


struct vlr_revocation_list_s {
  vlr_sys_param_ptr param;
  element_t A;
};

typedef struct vlr_revocation_list_s vlr_revocation_list_t[1];
typedef struct vlr_revocation_list_s *vlr_revocation_list_ptr;



void vlr_gen_sys_param(vlr_sys_param_ptr param, pairing_ptr pairing);
void vlr_gen(vlr_group_public_key_ptr gpk, vlr_group_revocation_token_t *grt, int n, vlr_user_private_key_t *usk, vlr_sys_param_ptr param);
void vlr_sign(unsigned char *sig,	int hashlen, void *hash, vlr_group_public_key_ptr gpk, vlr_user_private_key_ptr gsk);
int vlr_verify(unsigned char *sig, int hashlen, void *hash, vlr_group_public_key_t gpk, vlr_revocation_list_t *RL, int RLlen);
int vlr_revoc(int i, int n, vlr_group_revocation_token_t *grt, vlr_revocation_list_t *RL, int *RLlen);

void vlr_free_grt(vlr_group_revocation_token_t *grt, int n);
void vlr_free_usk(vlr_user_private_key_t *usk, int n);
void vlr_free_gpk(vlr_group_public_key_t gpk);

#ifdef __cplusplus
}
#endif

#endif
