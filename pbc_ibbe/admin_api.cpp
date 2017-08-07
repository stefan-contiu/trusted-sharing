#include "admin_api.h"
#include "spibbe.h"
#include "serialization.h"

std::string Configuration::CurveFile = "a.param";
int Configuration::UsersPerPartition;

std::string get_group_members_key(std::string groupName)
{
    return groupName + ".members";
}

std::string get_group_meta_key(std::string groupName)
{
    return groupName + ".meta";
}

AdminApi::AdminApi(std::string admin_name)
{
    // system set-up
    PublicKey pubKey;
    char* s[2] = {"main\0", "a.param\0" };
    setup_sgx_safe(&pubKey, &(this->spk), &(this->msk), Configuration::UsersPerPartition, 
        2, s);
        
    // todo : instantiate this with dependency injection
    this->cloud = new Cloud();
}

void AdminApi::CreateGroup(std::string groupName, std::vector<std::string> groupMembers)
{
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    
    // call sp-ibbe
    sp_ibbe_create_group(
        gpKeys, gpCiphers,
        this->spk, this->msk,
        groupMembers,
        Configuration::UsersPerPartition);
        
    // serialize members
    std::string s_members = serialize_members(groupMembers);
    
    // serialize gpKeys, gpCiphers
    std::string s_meta = serialize_group_metadata(gpKeys, gpCiphers);
    //printf("Meta size : %d\n", s_meta.size());

    // push the two group data to cloud
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
}

void AdminApi::AddUserToGroup(std::string groupName, std::string userName)
{
    // retreive data from cloud
    std::string s_members = this->cloud->get_text(get_group_members_key(groupName));
    std::string s_meta = this->cloud->get_text(get_group_meta_key(groupName));

    // deserialize
    std::vector<std::string> members;
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    deserialize_members(s_members, members);
    deserialize_group_metadata(s_meta, gpKeys, gpCiphers, this->spk.pairing);

    // add user
    sp_ibbe_add_user(this->spk, this->msk, gpKeys, gpCiphers, members, userName,
        Configuration::UsersPerPartition);
    
    // serialize 
    std::string new_s_members = serialize_members(members);
    std::string new_s_meta = serialize_group_metadata(gpKeys, gpCiphers);
    
    // push to cloud
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
}

void AdminApi::RemoveUserFromGroup(std::string groupName, std::string userName)
{
    // retreive data from cloud
    std::string s_members = this->cloud->get_text(get_group_members_key(groupName));
    std::string s_meta = this->cloud->get_text(get_group_meta_key(groupName));

    // deserialize
    std::vector<std::string> members;
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    deserialize_members(s_members, members);
    deserialize_group_metadata(s_meta, gpKeys, gpCiphers, this->spk.pairing);

    // remove user
    sp_ibbe_remove_user(this->spk, this->msk, gpKeys, gpCiphers, members, userName,
        Configuration::UsersPerPartition);
    
    // serialize 
    std::string new_s_members = serialize_members(members);
    std::string new_s_meta = serialize_group_metadata(gpKeys, gpCiphers);
    
    // push to cloud
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
}

AdminApi::~AdminApi()
{
    // TODO : any clean-up?
}
