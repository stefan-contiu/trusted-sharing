#include "admin_api.h"
#include "spibbe.h"
#include "serialization.h"
#include "microbench.h"
#include "admin_cache.h"
#include "pbc_test.h"

// TODO : remove the include once implementation is finished. It's only used for print_hex.
#include "sgx_crypto.h"

std::string Configuration::CurveFile = "a.param";
int Configuration::UsersPerPartition;

SpibbeApi::SpibbeApi(std::string admin_name, Cloud* cloud)
{
    //SystemSetup();
    LoadSystem();
    this->cloud = cloud;
}

void SpibbeApi::SystemSetup()
{
    char* s[2] = {"main\0", "a.param\0" };
    setup_sgx_safe(&(this->pk), &(this->spk), &(this->msk), Configuration::UsersPerPartition, 
        2, s);

    serialize_public_key_to_file(this->pk, "sys.pk");
    serialize_short_public_key_to_file(this->spk, "sys.spk");
    serialize_msk_to_file(this->msk, "sys.msk");
}

void SpibbeApi::LoadSystem()
{
    char* s[2] = {"main\0", "a.param\0" };
    
    pbc_demo_pairing_init(this->pk.pairing, 2, s);
    pbc_demo_pairing_init(this->spk.pairing, 2, s);

    deserialize_public_key_from_file("sys.pk", this->pk);
    deserialize_short_public_key_from_file("sys.spk", this->spk);
    deserialize_msk_from_file("sys.msk", this->msk, this->spk.pairing);
}

void SpibbeApi::CreateGroup(std::string groupName, std::vector<std::string> groupMembers)
{
    printf("-----> START CREATE GROUP \n");
    
    std::vector<SpibbePartition> partitions;

    /* ------------ SP-IBBE ------------ */
    unsigned char* g_key = sp_ibbe_create_group(
        partitions,
        this->spk, this->msk,
        groupMembers,
        Configuration::UsersPerPartition);      
    //printf("returned value "); print_hex(g_key, 32);

    /* ------------ SERIALIZATION ------------ */
    std::vector<std::string> names;
    std::vector<std::string> content;
    for (int p=0; p<partitions.size(); p++)
    {
        names.push_back(groupName + "/p" + std::to_string(p) + "/members.txt");
        content.push_back(serialize_partition_members(partitions[p]));
        
        names.push_back(groupName + "/p" + std::to_string(p) + "/meta.txt");
        content.push_back(serialize_partition_meta(partitions[p]));
    }

    /* ------------ PUSH TO CLOUD ------------ */
    this->cloud->put_multiple(names, content);

    /* ------------ PUSH TO LOCAL CACHE ------------ */
    for (int p=0; p<partitions.size(); p++)
        for (int i=0; i<partitions[p].members.size(); i++)
            AdminCache::PutUserPartition(groupName, partitions[p].members[i], p);
    memcpy(AdminCache::EnclaveGroupKey[groupName], g_key, 32);
            
    printf("-----> GROUP CREATED \n");
}

void SpibbeApi::AddUserToGroup(std::string groupName, std::string userName)
{
    printf("-----> START ADD USER TO GROUP \n");
 
    // find a non-empty partition for the user
    bool is_new_partition;
    int p = AdminCache::FindAvailablePartition(groupName, is_new_partition);

    SpibbePartition partition;
    if (!is_new_partition)
    {
        // retreive partition from cloud
        std::string members;
        std::string meta;
        this->cloud->get_partition(groupName, p, members, meta);
        
        // deserialize
        deserialize_partition(partition, members, meta, this->spk.pairing);    

        // SPIBBE - add user
        sp_ibbe_add_user(this->spk, this->msk, partition, userName);        
    }
    else
    {
        // retreive enclave protected key
        printf("returned value "); print_hex(AdminCache::EnclaveGroupKey[groupName], 32);
        
        // create a one user partition
        std::vector<std::string> singleMember;
        singleMember.push_back(userName);
        sp_ibbe_create_partition(partition, this->spk, this->msk, AdminCache::EnclaveGroupKey[groupName], singleMember);
    }
      
    // serialize 
    std::string new_s_members = serialize_partition_members(partition);
    std::string new_s_meta = serialize_partition_meta(partition);
   
    // push to cloud
    this->cloud->put_partition(groupName, p, new_s_members, new_s_meta);

    // push to admin cache
    AdminCache::PutUserPartition(groupName, userName, p);
 
    printf("-----> USER ADDED \n");
}

void SpibbeApi::RemoveUserFromGroup(std::string groupName, std::string userName)
{
    printf("-----> START REMOVE USER FROM GROUP \n");

    // get user partition
    int p = AdminCache::GetUserPartition(groupName, userName);
    int total_partitions = AdminCache::GetPartitionsCount(groupName);
    
    // retreive data from cloud; all metas; single user's members;
    std::vector<std::string> request_items;
    std::vector<std::string> responses;
    request_items.push_back(groupName + "/p" + std::to_string(p) + "/members.txt");
    for (int i=0; i<total_partitions; i++)
        request_items.push_back(groupName + "/p" + std::to_string(i) + "/meta.txt");
    this->cloud->get_multiple(request_items, responses);

    // deserialize all
    std::vector<SpibbePartition> partitions;
    for(int i=0; i<total_partitions; i++)
    {
        SpibbePartition partition;
        if (i == p)
        {
            deserialize_partition(partition, responses[0], responses[i+1], this->spk.pairing);
        }
        else
        {
            deserialize_partition(partition, "", responses[i+1], this->spk.pairing);
        }
        partitions.push_back(partition);
    }
        
    // remove user from current partition, re-key for the rest
    sp_ibbe_remove_user(this->spk, this->msk, partitions, userName, p);
    
    // serialize all and push to cloud
    std::vector<std::string> names;
    std::vector<std::string> content;
    for (int i=0; i<partitions.size(); i++)
    {
        if (i == p)
        {
            names.push_back(groupName + "/p" + std::to_string(i) + "/members.txt");
            content.push_back(serialize_partition_members(partitions[i]));
        }
        names.push_back(groupName + "/p" + std::to_string(i) + "/meta.txt");
        content.push_back(serialize_partition_meta(partitions[i]));
    }
    
    // push to cloud
    this->cloud->put_multiple(names, content);

    // cache changes
    AdminCache::RemoveUserFromPartition(groupName, userName, p);
    printf("-----> USER REMOVED \n");
}

void SpibbeApi::micro_get_upk(std::string user_id, UserPrivateKey upk)
{
    extract_sgx_safe(this->spk, this->msk, upk, (char*) user_id.c_str());
}


/*
 * USER API ----------------------------------------------------------
 */
SpibbeUserApi::SpibbeUserApi(std::string user_name, Cloud* cloud, SpibbeApi* admin)
{
    this->user_name = user_name;
    this->cloud = cloud;
    this->pk = admin->micro_get_pk();
    admin->micro_get_upk(user_name, this->upk);
}

void SpibbeUserApi::GetGroupKey(std::string groupName, GroupKey* groupKey)
{
#ifdef MICRO_DECRYPT
    struct timespec start, finish;
    start_clock
#endif     
    // retreive data from cloud
    std::string s_members = this->cloud->get_text(get_group_members_key(groupName));
    std::string s_meta = this->cloud->get_text(get_group_meta_key(groupName));
#ifdef MICRO_DECRYPT
    end_clock(m0) 
#endif 

#ifdef MICRO_DECRYPT
    start_clock
#endif     
    // deserialize
    std::vector<std::string> members;
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    deserialize_members(s_members, members);
    deserialize_group_metadata(s_meta, gpKeys, gpCiphers, this->pk.pairing);
#ifdef MICRO_REMOVE
    end_clock(m1) 
#endif

#ifdef MICRO_DECRYPT
    start_clock
#endif         
    // decrypt 
    sp_ibbe_user_decrypt(groupKey, gpKeys, gpCiphers, 
        this->pk,
        this->upk,
        this->user_name,
        members, 
        Configuration::UsersPerPartition);
#ifdef MICRO_REMOVE
    end_clock(m2)
    printf("DECRYPT_KEY,%d,%f,%f,%f\n", members.size(), m0, m1, m2);
#endif 
}