#include "inc/hash.h"


void hash_init(hash_ctx_t context)
{
    SHA256_Init(&context->context);
}

void hash_update(hash_ctx_t context, unsigned char *msg, unsigned int len)
{
    SHA256_Update(&context->context, msg, len);
}

void hash_final(unsigned char *digest, hash_ctx_t context)
{
    SHA256_Final(digest, &context->context);
}
