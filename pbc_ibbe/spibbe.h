#ifndef SP_IBBE_H
#define SP_IBBE_H

#include "ibbe.h"

#include <string>
#include <vector>

/* ---- RUNS IN SGX ---- */

int sp_ibbe_create_group(
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<std::string> members,
    int usersPerPartition);

/*
int sp_ibbe_add_user_to_partition(
    std::vector<std::string>& members,
    std::string user_id,
    Ciphertext& gpCipher,
    int usersPerPartition);
*/

int sp_ibbe_remove_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    std::vector<std::string>& members,
    std::string user_id,
    int usersPerPartition
);


/* ---- DOES NOT RUN IN SGX ---- */

int sp_ibbe_user_decrypt(
    GroupKey* gKey,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    PublicKey publicKey,
    UserPrivateKey userKey,
    std::string user_id,
    std::vector<std::string> members,
    int usersPerPartition);


// SP_IBBE_H
#endif
