/*
 *  TODO : The random and encryption methods need to by replaced with the
 *          SGX correspondents !!!
 *  TODO : define partition and user lookup methods
 *  TODO : modify add operation to consider lookup in partition
 *  TODO : refactor encryption methods into same calls
 *  TODO : protect MSK by enclave private key
 *  TODO : group signature scheme for the enclaves
 */

#include "ibbe.h"
#include "spibbe.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <algorithm>

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

void sgx_aes_encrypt(
    unsigned char* plaintext,
    int plaintext_size,
    unsigned char* key, unsigned char* iv,
    unsigned char* ciphertext)
{
    int len;
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

int sp_ibbe_create_group(
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<std::string> members,
    int usersPerPartition)
{
    // generate a random group key
    unsigned char* group_key = gen_random_bytestream(32);
    printf("CERATE GROUP KEY : ");
    print_hex(group_key, 32);

    // split idSet into partitions
    for (int p = 0; p * usersPerPartition < members.size(); p++)
    {
        int pStart = p * usersPerPartition;
        int pEnd   = pStart + usersPerPartition;
        if (pEnd > members.size())
        {
            pEnd = members.size();
        }

        printf("Partition from %d to %d ... \n", pStart, pEnd - 1);
        char idPartition[pEnd - pStart][MAX_STRING_LENGTH];
        for (int i=pStart; i<pEnd; i++)
        {
            memcpy(idPartition[i - pStart], members[i].c_str(), MAX_STRING_LENGTH);
        }

        // get a broadcast and ciphertext for the partition
        BroadcastKey bKey;
        Ciphertext bCipher;
        encrypt_sgx_safe(&bKey, &bCipher, pubKey, msk, idPartition, pEnd - pStart);
        printf("BKEY : "); print_hex(bKey, 32);

        // encrypt the group key by the broadcast key
        EncryptedGroupKey egk;
        sgx_random(16, egk.iv);
        sgx_aes_encrypt(group_key, 32, bKey, egk.iv, egk.encryptedKey);

        //egk.iv = gen_random_bytestream(16);
//      print_hex(iv, 16); print_hex(bKey, 32);
        //unsigned char encryptedKey[32];
        /*int len;
        int ciphertext_len;
        EVP_CIPHER_CTX *ctx;
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, bKey, egk.iv);
        EVP_EncryptUpdate(ctx, egk.encryptedKey, &len, group_key, 32);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, egk.encryptedKey + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);
*/
        // put the partition (encrytped key + iv) and ciphertext to return collections
        /*
        printf("KEY : ");
        print_hex(bKey, 32);

        printf("PLN : ");
        print_hex(group_key, 32);

        printf("CIP : ");
        print_hex(egk.encryptedKey, 32);
        */
        gpKeys.push_back(egk);
        gpCiphers.push_back(bCipher);

    }

    // clean-up if necessary
    printf("DONE CREATE GROUP\n");
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
        idCount = members.size() % usersPerPartition;
    }
    //printf("idCount = %d\n", idCount);

    char idSet[idCount][MAX_STRING_LENGTH];
    for (int i=0; i<idCount; i++)
    {
        int member_index = i + (usersPerPartition * userPartition);
        memcpy(idSet[i], members[member_index].c_str(), MAX_STRING_LENGTH);
    //    printf("%s\n", idSet[i]);
    }

    // derive a broadcast key based on partition
    BroadcastKey bKey;
    decrypt_user(&bKey, gpCiphers[userPartition], publicKey, userKey,
        user_id.c_str(), idSet, idCount);
    printf("BKEY : "); print_hex(bKey, 32);


    // decrypt the encrypted group key by partition broadcast key
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, bKey, gpKeys[userPartition].iv);
    EVP_DecryptUpdate(ctx, *gKey, &len, gpKeys[userPartition].encryptedKey, 32);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, (*gKey) + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    printf("USER DECRYTP KEY : "); print_hex(*gKey, 32);
}

/*
int sp_ibbe_add_user(std::vector<std::string>& members)
{
    // should we add to the last partition or create a new one
    if (members.size() % usersPerPartition == 0)
    {
        // create new partition, push to cloud
    }
    else
    {

    }
}
*/

int sp_ibbe_remove_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    std::vector<std::string>& members,
    std::string user_id,
    int usersPerPartition)
{
    // generate new AES key
    unsigned char* group_key = gen_random_bytestream(32);

    // find the partition of the user
    int totalPartitions = get_partitions_count(members, usersPerPartition);
    int userPartition = get_user_partition(members, user_id, usersPerPartition);

    // for all the un-touched partitions, do an optimized re-key in O(1)
    for (int p = 0; p < totalPartitions; p++)
    {
        // skip user partition and last one, they are treated by special case below
        if (p != userPartition && p != totalPartitions - 1)
        {
            // re-key the broadcast key
            BroadcastKey bKey;
            rekey_sgx_safe(&bKey, &(gpCiphers[p]), pubKey, msk);

            // encrypt the new group key by broadcast key
            sgx_random(16, gpKeys[p].iv);
            sgx_aes_encrypt(group_key, 32, bKey, gpKeys[p].iv, gpKeys[p].encryptedKey);
        }
    }

    // remove user from user partition
    BroadcastKey user_partition_key;
    remove_user_sgx_safe(&user_partition_key, &(gpCiphers[userPartition]),
        (char*)user_id.c_str(),
        pubKey, msk);
    sgx_random(16, gpKeys[userPartition].iv);
    sgx_aes_encrypt(group_key, 32, user_partition_key,
        gpKeys[userPartition].iv, gpKeys[userPartition].encryptedKey);

    // add last member to the user partition
    std::string last_user = members[members.size() - 1];
    if (userPartition < totalPartitions)
    {
        // include last member in user partition
        add_user_sgx_safe(&(gpCiphers[userPartition]), msk, (char*)last_user.c_str());

        // remove last member from last partition
        BroadcastKey last_partition_key;
        remove_user_sgx_safe(
            &last_partition_key,
            &(gpCiphers[totalPartitions - 1]),
            (char*) last_user.c_str(),
            pubKey, msk);
        sgx_random(16, gpKeys[totalPartitions - 1].iv);
        sgx_aes_encrypt(group_key, 32, last_partition_key,
            gpKeys[totalPartitions - 1].iv, gpKeys[totalPartitions - 1].encryptedKey);

    }

    // change the members list
    members[get_user_index(members, user_id)] = last_user;
    members.pop_back();
}
