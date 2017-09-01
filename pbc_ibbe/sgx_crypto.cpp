#include "sgx_crypto.h"
#include <stdlib.h>
#include <unistd.h>

unsigned char* gen_random_bytestream(int n)
{
    unsigned char* stream = (unsigned char*) malloc(n + 1);
    size_t i;
    for (i = 0; i < n; i++)
    {
        stream[i] = (unsigned char) (rand() % 255 + 1);
    }
    stream[n] = 0;
    return stream;
}