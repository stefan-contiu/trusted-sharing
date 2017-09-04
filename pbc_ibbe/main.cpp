#include "tests.h"
#include "admin_api.h"
#include "hybrid_api.h"
#include <stdio.h>

void sp_ibbe_functional_tests()
{
    char* s[2] = {"main\0", "a.param\0"};    
    ftest_one_user(2, s);
	ftest_create_group_decrypt_all(2, s, 30, 10);
    ftest_add_users_decrypt_all(2, s, 20, 10);
    ftest_remove_decrypt_all(2, s, 20, 9);
}

void api_tests()
{
    admin_api(1000, 1000);
}

void all_functional_tests()
{
    sp_ibbe_functional_tests();
    api_tests();
}

int main(int argc, char **argv)
{
    // make sure to run BVTs when doing lower level changes
    // all_functional_tests();

    micro_create_group(new SpibbeApi("master", new RedisCloud()));
    micro_create_group(new HybridApi("master", new RedisCloud()));
  
    micro_add_user(new SpibbeApi("master", new RedisCloud()));
    micro_add_user(new HybridApi("master", new RedisCloud()));
    
    micro_remove_user(new SpibbeApi("master", new RedisCloud()));
    micro_remove_user(new HybridApi("master", new RedisCloud()));
}
