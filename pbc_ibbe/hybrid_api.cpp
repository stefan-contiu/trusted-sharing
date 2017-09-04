#include "hybrid_api.h"
#include "hybrid_sgx.h"
#include "serialization.h"
#include "microbench.h"

HybridApi::HybridApi(std::string admin_name, Cloud* cloud)
{
    this->cloud = cloud;
}

HybridApi::~HybridApi()
{
}

void HybridApi::CreateGroup(std::string groupName, std::vector<std::string> groupMembers)
{
#ifdef MICRO_CREATE
    struct timespec start, finish;
    start_clock
#endif 
    // create group
    std::vector<std::string> encryptedKeys;
    hybrid_sgx_create_group(groupMembers, encryptedKeys);
#ifdef MICRO_CREATE
    end_clock(m0) 
#endif 

#ifdef MICRO_CREATE 
    start_clock 
#endif 
    // serialization
    std::string s_members = serialize_members(groupMembers);
    std::string s_meta = serialize_hybrid_keys(encryptedKeys);
#ifdef MICRO_CREATE
    end_clock(m1)
#endif 

        /* ------------ PUSH TO CLOUD ------------ */
#ifdef MICRO_CREATE
    start_clock
#endif 
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
#ifdef MICRO_CREATE
    end_clock(m2)
    printf("RSA_CREATE_GROUP,%d,%f,%f,%f\n", groupMembers.size(), m0, m1, m2);
#endif 

}

/* ----------------------------------------------------------------------------- */
void HybridApi::AddUserToGroup(std::string groupName, std::string userName)
{
#ifdef MICRO_ADD
    struct timespec start, finish;
    start_clock
#endif 
    // retreive data from cloud
    std::string k = get_group_members_key(groupName);
    std::string s_members = this->cloud->get_text(k);
    std::string s_meta = this->cloud->get_text(get_group_meta_key(groupName));
#ifdef MICRO_ADD
    end_clock(m0) 
#endif 

#ifdef MICRO_ADD
    start_clock
#endif 
    // deserialize
    std::vector<std::string> members;
    std::vector<std::string> encryptedKeys;
    deserialize_members(s_members, members);
    deserialize_hybrid_keys(s_meta, encryptedKeys);
#ifdef MICRO_ADD
    end_clock(m1) 
#endif 

#ifdef MICRO_ADD
    start_clock
#endif 
    // add user
    hybrid_sgx_add_user(members, encryptedKeys, userName);
#ifdef MICRO_ADD
    end_clock(m2) 
#endif 
    
#ifdef MICRO_ADD
    start_clock
#endif 
    // serialize 
    std::string new_s_members = serialize_members(members);
    std::string new_s_meta = serialize_hybrid_keys(encryptedKeys);
#ifdef MICRO_ADD
    end_clock(m3) 
#endif 
    
#ifdef MICRO_ADD
    start_clock
#endif 
    // push to cloud
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
#ifdef MICRO_ADD
    end_clock(m4) 
    printf("ADD_MEMBER,%d,%f,%f,%f,%f,%f\n", members.size(), m0, m1, m2, m3, m4);
#endif 
}

/* ----------------------------------------------------------------------------- */
void HybridApi::RemoveUserFromGroup(std::string groupName, std::string userName)
{
    // TODO : ...
}