#ifndef ADMIN_API_H
#define ADMIN_API_H

#include "ibbe.h"
#include "spibbe.h"
#include "cloud.h"

class AdminApi
{
    protected:
        std::string admin_name;
        Cloud* cloud;
            
    public:
        AdminApi() {}
        ~AdminApi() {}
        virtual void CreateGroup(std::string groupName, std::vector<std::string> groupMembers) = 0;
        virtual void AddUserToGroup(std::string groupName, std::string userName) = 0;
        virtual void RemoveUserFromGroup(std::string groupName, std::string userName) = 0;
};

class SpibbeApi : public AdminApi
{
    private:
        ShortPublicKey spk;
        MasterSecretKey msk;    
        
    public:
        SpibbeApi(std::string admin_name, Cloud* cloud);
        void CreateGroup(std::string groupName, std::vector<std::string> groupMembers);
        void AddUserToGroup(std::string groupName, std::string userName);
        void RemoveUserFromGroup(std::string groupName, std::string userName);
};

class UserApi
{
    private:
        PublicKey pk;
        UserPrivateKey upk;
        std::string user_name;
        Cloud* cloud;
        
    public:
        UserApi(std::string user_name, Cloud* cloud);
        ~UserApi() {}
        void GetGroupKey(std::string groupName, GroupKey* groupKey);
};

class Configuration
{
    public:
        static int UsersPerPartition;
        static std::string CurveFile;
};

// ADMIN_API_H
#endif