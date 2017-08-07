#ifndef TESTS_H
#define TESTS_H

/*
 *   FUNCTIONAL TESTS
 */
void ftest_one_user(int argc, char** argv);
void ftest_create_group_decrypt_all(int argc, char** argv, int g_size, int p_size);
void ftest_add_users_decrypt_all(int argc, char** argv, int g_size, int p_size);
void ftest_remove_decrypt_all(int argc, char** argv, int g_size, int p_size);
void ftest_add_remove_decrypt_all(int argc, char** argv, int g_size, int p_size);

void admin_api(int g_size, int p_size);

/*
 *   PERFORMANCE TESTS
 */

// MICROBENCHMARKS
void micro_spibbe_create_group();
void micro_spibbe_add_user();
void micro_spibbe_remove_user();
void micro_spibbe_decrypt_key();

void micro_rsa_create_group();
void micro_rsa_add_user();
void micro_rsa_remove_user();
void micro_rsa_decrypt_key();

void micro_keytree_create_group();
void micro_keytree_add_user();
void micro_keytree_remove_user();
void micro_keytree_decrypt_user();


// TESTS_H
#endif
