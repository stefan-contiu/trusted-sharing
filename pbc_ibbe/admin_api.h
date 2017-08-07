#ifndef ADMIN_API_H
#define ADMIN_API_H

#include "ibbe.h"
#include "spibbe.h"
#include "cloud.h"

class AdminApi
{
    private:
        ShortPublicKey spk;
        MasterSecretKey msk;
        std::string admin_name;
        Cloud* cloud;
            
    public:
        AdminApi(std::string admin_name);
        ~AdminApi();
        void CreateGroup(std::string groupName, std::vector<std::string> groupMembers);
        void AddUserToGroup(std::string groupName, std::string userName);
        void RemoveUserFromGroup(std::string groupName, std::string userName);
};

class Configuration
{
    public:
        static int UsersPerPartition;
        static std::string CurveFile;
};

// ADMIN_API_H
#endif