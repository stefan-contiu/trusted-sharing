#ifndef HYBRID_SGX_H
#define HYBRID_SGX_H

#include <vector>
#include <string>

void hybrid_sgx_create_group(std::vector<std::string> members, std::vector<std::string>& encryptedKeys);
void hybrid_sgx_add_user(std::vector<std::string>& members, std::vector<std::string>& encryptedKeys, std::string user_id);
void hybrid_sgx_remove_user();

// HYBRID_SGX_H
#endif