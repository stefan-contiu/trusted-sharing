#include "tests.h"
#include <stdio.h>

void sp_ibbe_functional_tests()
{
    char* s[2] = {"main\0", "a.param\0"};    
    ftest_one_user(2, s);
	ftest_create_group_decrypt_all(2, s, 30, 10);
    ftest_add_users_decrypt_all(2, s, 30, 10);
    ftest_remove_decrypt_all(2, s, 30, 8);
}

int main(int argc, char **argv)
{
    sp_ibbe_functional_tests();
}
