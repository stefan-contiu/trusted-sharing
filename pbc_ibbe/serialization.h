#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "ibbe.h"
#include "spibbe.h"

std::string serialize_members(std::vector<std::string>& members);
void deserialize_members(std::string s_members, std::vector<std::string>& members);

std::string serialize_group_metadata(std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c);
void deserialize_group_metadata(std::string s_meta, std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c, pairing_t pairing);

std::string serialize_public_key();
void deserialize_public_key();

std::string serialize_short_public_key();
void deserialize_short_public_key();

std::string serialize_user_key();
void deserialize_user_key();

std::string serialize_master_secret_key();
void deserialize_master_secret_key();

#endif