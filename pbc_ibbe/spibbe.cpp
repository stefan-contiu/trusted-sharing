/*
 *  TODO : The random and AES methods need to be replaced with the SGX ones.
 *  TODO : protect MSK by enclave private key.
 */

#include "sgx_crypto.h"
#include "ibbe.h"
#include "spibbe.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <algorithm>

const int Configuration::CipherElemSize;

void sgx_random(int n, unsigned char b[])
{
    size_t i;
    for (i = 0; i < n; i++)
    {
        b[i] = (unsigned char) (rand() % 255 + 1);
    }
}

int get_partitions_count(std::vector<std::string>& members, int usersPerPartition)
{
    int totalPartitions = members.size() / usersPerPartition;
    if (usersPerPartition * totalPartitions < members.size())
    {
        totalPartitions++;
    }
    return totalPartitions;
}

int get_user_partition(std::vector<std::string>& members, std::string user_id, int usersPerPartition)
{
    //printf("Get user partitino \n");
    int pos = std::find(members.begin(), members.end(), user_id) - members.begin();
    //printf("%d\n", pos);
    if (pos < members.size())
    {
        return pos / usersPerPartition;
    }
    else
    {
        printf("ERROR the user is not part of the group !\n");
        return -1;
    }
}

int get_user_index(std::vector<std::string>& members, std::string user_id)
{
    int pos = std::find(members.begin(), members.end(), user_id) - members.begin();
    if (pos < members.size())
    {
        return pos;
    }
    else
    {
        printf("ERROR the user is not part of the group !\n");
        return -1;
    }
}

unsigned char* sp_ibbe_create_group(
    std::vector<SpibbePartition>& partitions,
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<std::string>& members,
    int usersPerPartition)
{
    // generate a random group key
    unsigned char* group_key = gen_random_bytestream(32);
    printf("GKEY : "); print_hex(group_key, 32);

    // split idSet into partitions
    for (int p = 0; p * usersPerPartition < members.size(); p++)
    {
        SpibbePartition partition;
        
        int pStart = p * usersPerPartition;
        int pEnd   = pStart + usersPerPartition;
        if (pEnd > members.size())
        {
            pEnd = members.size();
        }

        char idPartition[pEnd - pStart][MAX_STRING_LENGTH];
        for (int i=pStart; i<pEnd; i++)
        {
            memcpy(idPartition[i - pStart], members[i].c_str(), MAX_STRING_LENGTH);
            partition.members.push_back(members[i]);
        }

        // get a broadcast and ciphertext for the partition
        BroadcastKey bKey;
        encrypt_sgx_safe(&bKey, &(partition.ciphertext), pubKey, msk, idPartition, pEnd - pStart); 

        // encrypt the group key by the broadcast key
        sgx_random(16, partition.encGroupKey.iv);
        sgx_aes_encrypt(group_key, 32, bKey, partition.encGroupKey.iv, partition.encGroupKey.encryptedKey);

        partitions.push_back(partition);
    }
    
    // TODO : encrypt group_key with enclave key before returning
    return group_key;
}

int sp_ibbe_create_partition(
    SpibbePartition& partition, 
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    GroupKey group_key,
    std::vector<std::string>& members)
{
    // TODO : decrypt group key by using SGX enclave key

    // HACK : scope of the method is currently for single users
    // create new partition for a single user
    BroadcastKey singleUserBKey;
    Ciphertext bCipher;
    char idSet[1][MAX_STRING_LENGTH];
    memcpy(idSet[0], members[0].c_str(), MAX_STRING_LENGTH);
    encrypt_sgx_safe(&singleUserBKey, &(partition.ciphertext), pubKey, msk, idSet, 1);

    // encrypt the group key by the new broadcast key
    EncryptedGroupKey egk;
    sgx_random(16, egk.iv);
    sgx_aes_encrypt(group_key, 32, singleUserBKey, partition.encGroupKey.iv, partition.encGroupKey.encryptedKey);

    partition.members.push_back(members[0]);
}

int sp_ibbe_user_decrypt(
    GroupKey* gKey,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    PublicKey publicKey,
    UserPrivateKey userKey,
    std::string user_id,
    std::vector<std::string> members,
    int usersPerPartition)
{
    int userPartition = get_user_partition(members, user_id, usersPerPartition);
    int totalPartitions = get_partitions_count(members, usersPerPartition);
    int idCount = usersPerPartition;
    if (userPartition == totalPartitions - 1)
    {
        idCount = members.size() - (userPartition * usersPerPartition);
    }

    char idSet[idCount][MAX_STRING_LENGTH];
    for (int i=0; i<idCount; i++)
    {
        int member_index = i + (usersPerPartition * userPartition);
        memcpy(idSet[i], members[member_index].c_str(), MAX_STRING_LENGTH);
    }

    // derive a broadcast key based on partition
    BroadcastKey bKey;
    decrypt_user(&bKey, gpCiphers[userPartition], publicKey, userKey,
        user_id.c_str(), idSet, idCount);

    // decrypt the encrypted group key by partition broadcast key
    sgx_aes_decrypt(gpKeys[userPartition].encryptedKey, 32, bKey,
        gpKeys[userPartition].iv, *gKey);
}

int sp_ibbe_add_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    SpibbePartition& partition,
    std::string user_id)
{
    add_user_sgx_safe(pubKey, &partition.ciphertext, msk, (char*) user_id.c_str());
    partition.members.push_back(user_id);
    return 0;
    
    /*
    // should we add to the last partition or create a new one
    if (partition.members.size() == 0)
    {
        // TODO : once SGX support is added, make sure to decrypt the group key
      
        // get the group_key by decrypting by first partition
        // TODO : O(m) decrypt should be a theorem
        BroadcastKey bKey;
        char firstPartition[usersPerPartition][MAX_STRING_LENGTH];
        for (int i = 0; i < usersPerPartition; i++)
        {
            memcpy(firstPartition[i], members[i].c_str(), MAX_STRING_LENGTH);
        }
        decrypt_sgx_safe(&bKey, gpCiphers[0], pubKey, msk,
            firstPartition, usersPerPartition);

        // decrypt the group key
        GroupKey group_key;
        sgx_aes_decrypt(gpKeys[0].encryptedKey, 32, bKey,
            gpKeys[0].iv, group_key);

        // create new partition for a single user
        BroadcastKey singleUserBKey;
        Ciphertext bCipher;
        char idSet[1][MAX_STRING_LENGTH];
        memcpy(idSet[0], user_id.c_str(), MAX_STRING_LENGTH);
        encrypt_sgx_safe(&singleUserBKey, &bCipher, pubKey, msk, idSet, 1);

        // encrypt the group key by the new broadcast key
        EncryptedGroupKey egk;
        sgx_random(16, egk.iv);
        sgx_aes_encrypt(group_key, 32, singleUserBKey, egk.iv, egk.encryptedKey);

        gpKeys.push_back(egk);
        gpCiphers.push_back(bCipher);
        
    }
    else
    {
        // add to existing last partition
        int p = get_partitions_count(partition.members, usersPerPartition);
        add_user_sgx_safe(pubKey, &(gpCiphers[p - 1]), msk, (char*) user_id.c_str());
    }
    members.push_back(user_id);
     */
}

int sp_ibbe_remove_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<SpibbePartition>& partitions,
    std::string user_id,
    int user_partition_index)
{
    // generate new AES key
    unsigned char* group_key = gen_random_bytestream(32);

    // for all un-touched partitions do an optimized re-key in O(1)
    for(int i=0; i<partitions.size(); i++)
        if (i != user_partition_index)
        {
            // re-key the broadcast key
            BroadcastKey bKey;
            rekey_sgx_safe(&bKey, &(partitions[i].ciphertext), pubKey, msk);

            // encrypt the new group key by broadcast key
            sgx_random(16, partitions[i].encGroupKey.iv);
            sgx_aes_encrypt(group_key, 32, bKey, partitions[i].encGroupKey.iv, partitions[i].encGroupKey.encryptedKey);
        }

    // for user partition, do an optimized remove in O(1)
    BroadcastKey user_partition_key;
    remove_user_sgx_safe(&user_partition_key, &(partitions[user_partition_index].ciphertext),
        (char*)user_id.c_str(),
        pubKey, msk);
    sgx_random(16, partitions[user_partition_index].encGroupKey.iv);
    sgx_aes_encrypt(group_key, 32, user_partition_key,
        partitions[user_partition_index].encGroupKey.iv, partitions[user_partition_index].encGroupKey.encryptedKey);
    if (partitions[user_partition_index].members.size() == 1)
    {
        partitions[user_partition_index].members.clear();
    }
    else
    {
        int usr_index = get_user_index(partitions[user_partition_index].members, user_id);
        int last_index = partitions[user_partition_index].members.size() - 1;
        partitions[user_partition_index].members[usr_index] = partitions[user_partition_index].members[last_index];
        partitions[user_partition_index].members.pop_back();
    }
}
