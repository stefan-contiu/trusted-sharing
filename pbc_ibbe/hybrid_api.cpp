#include "hybrid_api.h"
#include "hybrid_sgx.h"


HybridApi::HybridApi(std::string admin_name, Cloud* cloud)
{
    this->cloud = cloud;
}

HybridApi::~HybridApi()
{
}

void HybridApi::CreateGroup(std::string groupName, std::vector<std::string> members)
{
    printf("Long live Hybrid API\n");
    // get all the members public key from a PKI
    
    // create group
    std::vector<std::string> encryptedKeys;
    hybrid_sgx_create_group(members, encryptedKeys);

    // serialization
    // TODO : serialize all the keys into a big chunk

    // push to cloud
    // push 1. members
    // push 2. serialized ciphertext
}