
#include "pbc.h"
#include "ibbe.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

int create_group(
    GroupKeyEncryptedByPartitionKey** gpKeys, Ciphertext** gpCiphers,
    ShortPublicKey pubKey, MasterSecretKey msk,
    char idSet[][MAX_STRING_LENGTH], int idCount, int partitionCount);
