#include "cloud.h"

/*
 * TODO : make Cloud an interface and have Redis and Dropbox implement it.
 */

Cloud::Cloud()
{
    client.connect("127.0.0.1", 6379, [](cpp_redis::redis_client&) {
        printf("ERROR : Client Disconected !\n");
    });
}

Cloud::~Cloud()
{
    client.disconnect();
}

void Cloud::put_text(std::string key, std::string value)
{
    printf("Saving to REDIS : %s\n", key.c_str());
    client.set(key, value);
    client.commit();
}
    
std::string Cloud::get_text(std::string key)
{
    client.get(key, [](cpp_redis::reply& reply) {
        return reply.as_string();
    });
}