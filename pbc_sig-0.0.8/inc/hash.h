#ifndef __PBC_HASH_H__
#define __PBC_HASH_H__

#ifdef __cplusplus
extern "C"{
#endif

#include <openssl/sha.h>

struct hash_ctx_s {
    SHA256_CTX context;
};
typedef struct hash_ctx_s hash_ctx_t[1];
typedef struct hash_ctx_s *hash_ctx_ptr;

void hash_init(hash_ctx_t context);
void hash_update(hash_ctx_t context, unsigned char *msg, unsigned int len);
void hash_final(unsigned char *digest, hash_ctx_t context);

enum {
    hash_length = SHA256_DIGEST_LENGTH,
};

#ifdef __cplusplus
}
#endif
#endif //__PBC_HASH_H__
