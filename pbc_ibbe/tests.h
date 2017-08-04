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

/*
 *   PERFORMANCE TESTS
 */

// TESTS_H
#endif
