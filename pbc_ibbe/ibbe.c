/*
 *  Implementation of SP-IBBE,
 *  i.e. Secured & Partitioned - Identity Based Broadcast Encryption.
 *
 *  Author: Stefan Contiu <stefan.contiu@u-bordeaux.fr>
 *
 *  Published under Apache v2 License:
 *      https://www.apache.org/licenses/LICENSE-2.0.txt
 */

#include "ibbe.h"
#include "pbc_test.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

pairing_t pairing;

int setup_sgx_safe(PublicKey *puk, ShortPublicKey *spuk, MasterSecretKey *msk, int max_group_size, int argc, char** argv)
{
    int i;
    element_t g, h;
    element_t w, v;
    element_t gamma;
    element_t temp1;
    element_t *hRec;

    // load pairing from arguments
    {
        srand(time(NULL));
        pbc_random_set_deterministic(rand());
        pbc_demo_pairing_init(pairing, argc, argv);
    }

    element_init_G1(g, pairing);
    element_init_G2(h, pairing);
    element_init_G1(w, pairing);
    element_init_GT(v, pairing);
    element_init_Zr(gamma, pairing);
    element_init_Zr(temp1, pairing);

    // generate random values
    {
        element_random(g);
        element_random(h);
        element_random(gamma);
    }

    // compute w and v
    {
        element_pow_zn(w, g, gamma);
        element_pairing(v, g, h);
    }

    // compute public key h sequence
    {
        hRec = (element_t*)malloc(sizeof(element_t) * (max_group_size + 2));
        mpz_t n;
        mpz_init(n);
        for (i = 0; i <= max_group_size; i++)
        {
            element_init_G2(hRec[i], pairing);
            mpz_set_ui(n, (unsigned int)i);
            element_pow_mpz(temp1, gamma, n);
            element_pow_zn(hRec[i], h, temp1);
        }
        mpz_clear(n);

        puk->h = hRec;
        puk->h_size = max_group_size + 2;
        element_init_G1(puk->w, pairing);
        element_init_GT(puk->v, pairing);
        element_set(puk->w, w);
        element_set(puk->v, v);
    }

    // define master secret key
    {
        element_init_G1(msk->g, pairing);
        element_init_Zr(msk->gamma, pairing);
        element_set(msk->g, g);
        element_set(msk->gamma, gamma);
    }

    // define the short SGX safe public key
    {
        element_init_G1(spuk->w, pairing);
        element_init_GT(spuk->v, pairing);
        element_init_G1(spuk->h, pairing);
        element_set(spuk->w, puk->w);
        element_set(spuk->v, puk->v);
        element_set(spuk->h, puk->h[0]);
        int hlen = element_length_in_bytes(puk->h[0]);
        //printf("Pub key element size (bytes): %d\n", hlen);
    }

    // clean-up
    element_clear(h);
    element_clear(temp1);

    return 0;
}

int extract_sgx_safe(MasterSecretKey msk, UserPrivateKey idkey, char* id)
{
    element_t hid;
    element_init_Zr(hid, pairing);
    element_init_G1(idkey, pairing);

    // compute gamma + hash
    element_from_hash(hid, id, strlen(id));
    element_add(hid, hid, msk.gamma);

    // invert and exponentiate g
    element_invert(hid, hid);
    element_pow_zn(idkey, msk.g, hid);

    element_clear(hid);
    return 0;
}


int encrypt_sgx_safe(BroadcastKey* bKey, Ciphertext *cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, char idSet[][MAX_STRING_LENGTH], int idCount)
{
    element_t k;
    element_t c1, c2, c3;
    element_t product;
    element_t hash;

    element_init_Zr(k, pairing);
    element_init_G1(c1, pairing);
    element_init_G2(c2, pairing);
    element_init_G2(c3, pairing);
    element_random(k);

    // compute C1
    {
        element_pow_zn(c1, pubKey.w, k);
        element_invert(c1, c1);
        //element_printf("C1 : %B\n", c1);
    }

    // compute C2 and C3
    {
        element_init_Zr(product, pairing);
        element_set1(product);
        for (int i = 0; i < idCount; i++)
        {
            // compute hash
            element_init_Zr(hash, pairing);
            element_from_hash(hash, idSet[i], strlen(idSet[i]));

            // sum hash with gamma and multiply into product
            element_add(hash, msk.gamma, hash);
            element_mul(product, product, hash);
        }

        // raise h at product
        element_pow_zn(c3, pubKey.h, product);

        // raise c3 at k
        element_pow_zn(c2, c3, k);


        /*
        // multiply whole product by k
        element_mul(product, product, k);

        // raise h to product
        element_pow_zn(c2, pubKey.h, product);
        //element_printf("C2 : %B\n", c2);
        */
    }

    // compute BroadcastKey
    {
        element_t key_element;
        element_init_GT(key_element, pairing);
        element_pow_zn(key_element, pubKey.v, k);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(key_element);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, key_element);
        SHA256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    element_init_G1(cipher->c1, pairing);
    element_init_G1(cipher->c2, pairing);
    element_init_G1(cipher->h_pow_product_gamma_hash, pairing);
    element_set(cipher->c1, c1);
    element_set(cipher->c2, c2);
    element_set(cipher->h_pow_product_gamma_hash, c3);

    element_clear(k);
    element_clear(c1);
    element_clear(c2);
    element_clear(hash);
    element_clear(product);

    return 0;
}

// should have a correponding theorem in the paper.
int add_user_sgx_safe(Ciphertext *cipher, MasterSecretKey msk, char* id)
{
    element_t hash;
    element_init_Zr(hash, pairing);
    element_from_hash(hash, id, strlen(id));

    element_add(hash, hash, msk.gamma);
    element_pow_zn(cipher->c2, cipher->c2, hash);
    element_pow_zn(cipher->h_pow_product_gamma_hash, cipher->h_pow_product_gamma_hash, hash);

    element_clear(hash);
    return 0;
}

// should have a corresponding theorem in the paper
int rekey_user_sgx_safe(BroadcastKey* bKey, Ciphertext *cipher, ShortPublicKey spk, MasterSecretKey msk)
{
    // generate a new k
    element_t k;
    {
        element_init_Zr(k, pairing);
        element_random(k);
    }

    // compute new Ciphertext elements
    {
        // c1
        element_pow_zn(cipher->c1, spk.w, k);
        element_invert(cipher->c1, cipher->c1);

        // c2
        element_pow_zn(cipher->c2, cipher->h_pow_product_gamma_hash, k);
    }

    // compute new boradcast key K
    {
        element_t key_element;
        element_init_GT(key_element, pairing);
        element_pow_zn(key_element, spk.v, k);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(key_element);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, key_element);
        SHA256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    element_clear(k);
    return 0;
}

int decrypt_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk,
    char idSet[][MAX_STRING_LENGTH], int idCount)
{
    element_t e_1, e_2;
    element_t product, hash;

    element_init_GT(e_1, pairing);
    element_init_GT(e_2, pairing);

    // compute the exponent
    {
        element_init_Zr(product, pairing);
        element_set1(product);
        for (int i = 0; i < idCount; i++)
        {
            // compute hash
            element_init_Zr(hash, pairing);
            element_from_hash(hash, idSet[i], strlen(idSet[i]));

            // sum hash with gamma and multiply into product
            element_add(hash, msk.gamma, hash);
            element_mul(product, product, hash);
        }

        element_sub(product, product, msk.gamma);
        element_invert(product, product);
    }

    // compute the pairings
    {
        element_pairing(e_1, cipher.c1, pubKey.h);
        element_pairing(e_2, msk.g, cipher.c2);
        element_mul(e_1, e_1, e_2);
    }

    // compute key
    {
        element_pow_zn(e_1, e_1, product);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(e_1);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, e_1);
        SHA256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    // clean-up
    {
        element_clear(e_1);
        element_clear(e_2);
        element_clear(product);
        element_clear(hash);
    }
}

int decrypt_with_key_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount)
{
    element_t e_1, e_2;
    element_t sub_uni_exp;
    element_t hash;
    element_t p_hash, p_gamma_hash, p_term;
    element_t h_exp;
    element_t e1_hp;

    element_init_GT(e_1, pairing);
    element_init_GT(e_2, pairing);
    element_init_Zr(sub_uni_exp, pairing);
    element_init_Zr(h_exp, pairing);
    element_init_G2(e1_hp, pairing);

    // compute the p exponent used by the first pairing
    {
        element_init_Zr(p_hash, pairing);
        element_init_Zr(p_gamma_hash, pairing);
        element_init_Zr(p_term, pairing);
        element_set1(p_hash);
        element_set1(p_gamma_hash);
        for (int i = 0; i < idCount; i++)
        {
            // exclude the current user
            if (strcmp(id, idSet[i]) != 0)
            {
                // compute hash
                element_init_Zr(hash, pairing);
                element_from_hash(hash, idSet[i], strlen(idSet[i]));

                // include hash in products
                element_mul(p_hash, p_hash, hash);
                element_add(p_term, hash, msk.gamma);
                element_mul(p_gamma_hash, p_gamma_hash, p_term);
            }
        }

        // multiply 1/gamma with (p_gamma_hash - p_hash)
        element_sub(p_gamma_hash, p_gamma_hash, p_hash);
        element_set(h_exp, msk.gamma);
        element_invert(h_exp, h_exp);
        element_mul(h_exp, h_exp, p_gamma_hash);
        element_pow_zn(e1_hp, pubKey.h, h_exp);
    }

    // compute the product of the two pairings
    {
        element_pairing(e_1, cipher.c1, e1_hp);
        element_pairing(e_2, ikey, cipher.c2);
        element_mul(e_1, e_1, e_2);
    }

    // finally compute key, serialize to bytes and SHA
    {
        element_set(sub_uni_exp, p_hash);
        element_invert(sub_uni_exp, sub_uni_exp);
        element_pow_zn(e_1, e_1, sub_uni_exp);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(e_1);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, e_1);
        SHA256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    // clean up
    element_clear(e_1);
    element_clear(e_2);
    element_clear(sub_uni_exp);
    element_clear(hash);
    element_clear(p_hash);
    element_clear(p_gamma_hash);
    element_clear(p_term);
    return 0;
}

int decrypt_user_no_optimizations(BroadcastKey* bKey, Ciphertext cipher, PublicKey key, UserPrivateKey ikey, char* id, char idSet[][MAX_STRING_LENGTH], int idNum)
{
    int i, j;
    int mark = 1;
    char **decryptUsrSet = (char**)malloc(sizeof(char*) * (idNum - 1));
    for (i = 0, j = 0; i < idNum; i++)
    {
        if (strcmp(id, idSet[i]) != 0)
        {
            decryptUsrSet[j] = (char*)malloc(sizeof(char) * MAX_STRING_LENGTH);
            memcpy(decryptUsrSet[j], idSet[i], MAX_STRING_LENGTH);
            j++;
        }
    }

    element_t htemp1, htemp2;
    element_t temp1, temp2;
    element_t ztemp;

    element_init_G1(htemp1, pairing);
    element_init_G1(htemp2, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_Zr(ztemp, pairing);

    element_t *hid;
    {
        /* polynominal multiplication */
        /***************************************/
        element_t *polyA, *polyB;
        polyA = (element_t*)malloc(sizeof(element_t) * idNum);
        polyB = (element_t*)malloc(sizeof(element_t) * idNum);
        hid = (element_t*)malloc(sizeof(element_t) * idNum-1);
        /*initialization*/
        for (i = 0; i < idNum; i++)
        {
            element_init_Zr(polyA[i], pairing);
            element_set0(polyA[i]);
            element_init_Zr(polyB[i], pairing);
            element_set0(polyB[i]);
            element_init_Zr(hid[i], pairing);
            if (i < idNum - 1)
                element_from_hash(hid[i], decryptUsrSet[i], strlen(decryptUsrSet[i]));
        }
        /*calculation*/
        if (idNum == 1)
        {
            /*dealing with only 1 receiver*/
            element_set(htemp1, key.h[idNum+1]);
        }
        else
        {
            element_set(polyA[0], hid[0]);
            element_set1(polyA[1]);
            for (i = 1; i < idNum - 1; i++)
            {
                /*i-th polynomial*/
                /*polyA * (r + H(ID))*/
                element_set1(polyA[i+1]);
                for (j = i; j >= 1; j--)
                {
                    element_mul(polyB[j], polyA[j], hid[i]);
                    element_add(polyA[j], polyA[j-1], polyB[j]);
                }
                element_mul(polyA[0], polyA[0], hid[i]);
            }
            element_set1(htemp1);
            for (i = 0; i < idNum-1; i++)
            {
                element_pow_zn(htemp2, key.h[i], polyA[i+1]);
                element_mul(htemp1, htemp1, htemp2);
            }
        }
        /*
        free(polyA);
        free(polyB);
        */
    }

    element_pairing(temp1, cipher.c1, htemp1);
    element_pairing(temp2, ikey, cipher.c2);
    element_mul(temp1, temp1, temp2);

    element_set1(ztemp);
    for (i = 0; i < idNum - 1; i++)
    {
        element_mul(ztemp, ztemp, hid[i]);
    }
    element_invert(ztemp, ztemp);

    /* K */
    element_pow_zn(temp1, temp1, ztemp);

    // serialize to bytes and do a SHA
    int generated_key_length = element_length_in_bytes(temp1);
    unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
    element_to_bytes(key_element_bytes, temp1);
    SHA256(key_element_bytes, generated_key_length, *bKey);
    free(key_element_bytes);

    free(hid);
    element_clear(htemp1);
    element_clear(htemp2);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(ztemp);

    return 0;
}

// --- MULTITHREADING OPTIMIZATIONS ---

struct exp_part_struct {
    int start;
    int end;
    PublicKey key;
    element_t* polyA;
};

void *decrypt_exponentiate_by_partition(void *pargs)
{
    struct exp_part_struct *args = (struct exp_part_struct *)pargs;

    /* old style exponentiation */
    element_t thread_temp2;

    element_t* ptemp = (element_t*) malloc(sizeof(element_t));
    element_init_G1(*ptemp, pairing);
    element_set1(*ptemp);

    element_init_G1(thread_temp2, pairing);

    int i;
    for (i = args->start; i <= args->end - 3; i+=3)
    {
        element_pow3_zn(thread_temp2,
            args->key.h[i], args->polyA[i+1],
            args->key.h[i+1], args->polyA[i+2],
            args->key.h[i+2], args->polyA[i+3]);
        element_mul(*ptemp, *ptemp, thread_temp2);
    }
    // exponentiate and multiply any leftovers
    if (i <= args->end)
    {
        for (int j = i; j <= args->end; j++)
        {
            element_pow_zn(thread_temp2, args->key.h[j], args->polyA[j+1]);
            element_mul(*ptemp, *ptemp, thread_temp2);
        }
    }

    pthread_exit(ptemp);
    return (void*) ptemp;
}

int decrypt_user(BroadcastKey* bKey, Ciphertext cipher, PublicKey key, UserPrivateKey ikey, const char* id, char idSet[][MAX_STRING_LENGTH], int idCount)
{
    int i, j;
    int mark = 1;
    char **decryptUsrSet = (char**)malloc(sizeof(char*) * (idCount - 1));
    for (i = 0, j = 0; i < idCount; i++)
    {
        if (strcmp(id, idSet[i]) != 0)
        {
            decryptUsrSet[j] = (char*)malloc(sizeof(char) * MAX_STRING_LENGTH);
            memcpy(decryptUsrSet[j], idSet[i], MAX_STRING_LENGTH);
            j++;
        }
    }

    element_t htemp1, htemp2;
    element_t temp1, temp2;
    element_t ztemp;

    element_init_G1(htemp1, pairing);
    element_init_G1(htemp2, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_Zr(ztemp, pairing);

    element_t *hid;
    {
        /*polynominal multiplication */
        /***************************************/
        element_t *polyA, *polyB;
        polyA = (element_t*)malloc(sizeof(element_t) * idCount);
        polyB = (element_t*)malloc(sizeof(element_t) * idCount);
        hid = (element_t*)malloc(sizeof(element_t) * idCount - 1);
        /*initialization*/
        for (i = 0; i < idCount; i++)
        {
            element_init_Zr(polyA[i], pairing);
            element_set0(polyA[i]);
            element_init_Zr(polyB[i], pairing);
            element_set0(polyB[i]);
            element_init_Zr(hid[i], pairing);
            if (i < idCount - 1)
                element_from_hash(hid[i], decryptUsrSet[i], strlen(decryptUsrSet[i]));
        }

        element_set(polyA[0], hid[0]);
        element_set1(polyA[1]);
        for (i = 1; i < idCount - 1; i++)
        {
            /*i-th polynomial*/
            /*polyA * (r + H(ID))*/
            element_set1(polyA[i+1]);
            for (j = i; j >= 1; j--)
            {
                element_mul(polyB[j], polyA[j], hid[i]);
                element_add(polyA[j], polyA[j-1], polyB[j]);
            }
            element_mul(polyA[0], polyA[0], hid[i]);
        }
        element_set1(htemp1);

        // multithreading
        {
            int idNum = idCount - 2;
            int exp_per_partition = (idNum / THREADS_COUNT) + 1;

            pthread_t tid[THREADS_COUNT];
            for(int thread_idx = 0; thread_idx < THREADS_COUNT; thread_idx++)
            {
                // compute the partition of exponentiations
                struct exp_part_struct* args = (struct exp_part_struct*) malloc (sizeof (struct exp_part_struct));
                args->key = key;
                args->polyA = polyA;
                args->start = thread_idx * exp_per_partition;
                args->end = args->start + exp_per_partition - 1;
                if (args->end > idNum)
                {
                    args->end = idNum;
                }

                pthread_create(&tid[thread_idx], NULL, decrypt_exponentiate_by_partition, (void *)args);
            }

            element_t result;
            element_init_G1(result, pairing);
            element_set1(result);
            // wait that threads are complete
            for(int thread_idx = 0; thread_idx < THREADS_COUNT; thread_idx++)
            {
                void* partition_result;
                pthread_join(tid[thread_idx], &partition_result);
                element_mul(htemp1, htemp1, *(element_t*)partition_result);
            }
        }
        /*
        free(polyA);
        free(polyB);
        */
    }

    element_pairing(temp1, cipher.c1, htemp1);
    element_pairing(temp2, ikey, cipher.c2);
    element_mul(temp1, temp1, temp2);

    element_set1(ztemp);
    for (i = 0; i < idCount - 1; i++)
    {
        element_mul(ztemp, ztemp, hid[i]);
    }
    element_invert(ztemp, ztemp);

    /* K */
    element_pow_zn(temp1, temp1, ztemp);

    // serialize to bytes and do a SHA
    int generated_key_length = element_length_in_bytes(temp1);
    unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
    element_to_bytes(key_element_bytes, temp1);
    SHA256(key_element_bytes, generated_key_length, *bKey);
    free(key_element_bytes);

    free(hid);
    element_clear(htemp1);
    element_clear(htemp2);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(ztemp);

    return 0;
}

void serialize_public_key(PublicKey pk, unsigned char* s, int* s_count)
{
    printf("START SERIALIZING INSIDE ....\n");
    s = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE * (2 + pk.h_size));
    int offset = 0;

    // save w
    unsigned char* w_bytes = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE);
    element_to_bytes(w_bytes, pk.w);
    memcpy(s, w_bytes, PAIRING_ELEMENT_SIZE);
    offset += PAIRING_ELEMENT_SIZE;
    free(w_bytes);

    // save v
    unsigned char* v_bytes = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE);
    element_to_bytes(v_bytes, pk.v);
    memcpy(s + offset, v_bytes, PAIRING_ELEMENT_SIZE);
    offset += PAIRING_ELEMENT_SIZE;
    free(v_bytes);

    // save h
    for(int i = 0; i < pk.h_size - 1; i++)
    {
        unsigned char* h_bytes = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE);
        element_to_bytes(w_bytes, pk.h[i]);
        memcpy(s + offset, w_bytes, PAIRING_ELEMENT_SIZE);
        offset += PAIRING_ELEMENT_SIZE;
        free(h_bytes);
    }

    *s_count = offset;
    printf("PK SER SIZE : %d\n", *s_count);
}

void serialize_short_public_key(ShortPublicKey spk, unsigned char* s, int* s_count)
{
    s = (unsigned char*) malloc(3 * PAIRING_ELEMENT_SIZE);
    int offset = 0;

    // save w
    unsigned char* w_bytes = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE);
    element_to_bytes(w_bytes, spk.w);
    memcpy(s, w_bytes, PAIRING_ELEMENT_SIZE);
    offset += PAIRING_ELEMENT_SIZE;
    free(w_bytes);

    // save v
    unsigned char* v_bytes = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE);
    element_to_bytes(v_bytes, spk.v);
    memcpy(s + offset, v_bytes, PAIRING_ELEMENT_SIZE);
    offset += PAIRING_ELEMENT_SIZE;
    free(v_bytes);

    // save h
    unsigned char* h_bytes = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE);
    element_to_bytes(h_bytes, spk.v);
    memcpy(s + offset, h_bytes, PAIRING_ELEMENT_SIZE);
    offset += PAIRING_ELEMENT_SIZE;
    free(h_bytes);

    *s_count = offset;
}

void serialize_master_secret_key(MasterSecretKey msk, unsigned char* s, int* s_count)
{
    s = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE + ZN_ELEMENT_SIZE);
    int offset = 0;

    // save g
    unsigned char* g_bytes = (unsigned char*) malloc(PAIRING_ELEMENT_SIZE);
    element_to_bytes(g_bytes, msk.g);
    memcpy(s, g_bytes, PAIRING_ELEMENT_SIZE);
    offset += PAIRING_ELEMENT_SIZE;
    free(g_bytes);

    // save gamma
    unsigned char* gamma_bytes = (unsigned char*) malloc(ZN_ELEMENT_SIZE);
    element_to_bytes(gamma_bytes, msk.gamma);
    memcpy(s + offset, gamma_bytes, ZN_ELEMENT_SIZE);
    offset += ZN_ELEMENT_SIZE;
    free(gamma_bytes);

    *s_count = offset;
}

void serialize_cipher(Ciphertext c, unsigned char* s, int* s_count)
{
    printf("C1 : %d \n", element_length_in_bytes(c.c1));
    printf("C2 : %d \n", element_length_in_bytes(c.c2));
    printf("CH : %d \n", element_length_in_bytes(c.h_pow_product_gamma_hash));
    //s = (unsigned char*) malloc(64);
}

void deserialize_public_key(unsigned char s[], PublicKey* pk)
{

}

void deserialize_short_public_key(unsigned char s[], ShortPublicKey* spk)
{

}

void deserialize_master_secret_key(unsigned char s[], MasterSecretKey* msk)
{

}

void deserialize_cipher(unsigned char s[], Ciphertext* c)
{

}

unsigned char* gen_random_bytestream(int n)
{
    unsigned char* stream = (unsigned char*) malloc(n + 1);
    size_t i;
    for (i = 0; i < n; i++)
    {
        stream[i] = (unsigned char) (rand() % 255 + 1);
    }
    stream[n] = 0;
    return stream;
}

/*
int create_group(
    GroupKeyEncryptedByPartitionKey** gpKeys, Ciphertext** gpCiphers,
    ShortPublicKey pubKey, MasterSecretKeyCipher mskCipher,
    char idSet[][MAX_STRING_LENGTH], int idCount, int partitionCount)
{
    // decrypt the master secret key (system) by the enclave key
    MasterSecretKey msk;

    //
    create_group_sgx_safe(gpKeys, gpCiphers, pubKey, msk,
        idSet, idCount, partitionCount);
}
*/

int enclave_create_group(
    GroupKeyEncryptedByPartitionKey gpKeys[], Ciphertext gpCiphers[],
    ShortPublicKey pubKey, MasterSecretKey msk,
    //char idSet[][MAX_STRING_LENGTH], int idCount, int usersPerPartition)
    char **idSet, int idCount, int usersPerPartition)
{
    // generate a random group key
    unsigned char* group_key = gen_random_bytestream(32);
    //printf("RND GRP KEY : ");
    //print_hex(group_key, 32);

    // split idSet into partitions
    for (int p = 0; p * usersPerPartition < idCount; p++)
    {
        int pStart = p * usersPerPartition;
        int pEnd   = pStart + usersPerPartition;
//        printf("Partition from %d to %d ... \n", pStart, pEnd - 1);
        char idPartition[usersPerPartition][MAX_STRING_LENGTH];
        //printf("ALLOCATED ... \n");

        for (int i=pStart; i<pEnd; i++)
        {
            memcpy(idPartition[i - pStart], idSet[i], MAX_STRING_LENGTH);
        }

        // get a broadcast and ciphertext for the partition
        BroadcastKey bKey;
        Ciphertext bCipher;
        //for(int i=0; i<usersPerPartition; i++)
        //    printf("ENC : %s\n", idPartition[i]);//idPartition[i]);
        encrypt_sgx_safe(&bKey, &bCipher, pubKey, msk, idPartition, usersPerPartition);

        // encrypt the group key by the broadcast key
        unsigned char* iv = gen_random_bytestream(16);
//        print_hex(iv, 16);
//        print_hex(bKey, 32);
        unsigned char encryptedKey[48];
        int len;
        int ciphertext_len;
        EVP_CIPHER_CTX *ctx;
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx,  EVP_aes_256_ctr(), NULL, bKey, iv);
        EVP_EncryptUpdate(ctx, encryptedKey, &len, group_key, 32);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, encryptedKey + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        // put the partition (encrytped key + iv) and ciphertext to return collections
/*
        printf("KEY : ");
        print_hex(bKey, 32);

        printf("PLN : ");
        print_hex(group_key, 32);

        printf("CIP : ");
        print_hex(encryptedKey, 32);
*/

        //print_hex(encryptedKey, 32);



        memcpy(gpKeys[p], encryptedKey, 32);
        memcpy(gpKeys[p] + 32, iv, 16);
        gpCiphers[p] = bCipher;
    }

    // clean-up if necessary
}

int user_decrypt_group_key(
    GroupKey* gKey,
    GroupKeyEncryptedByPartitionKey partEncKey, Ciphertext partCipher,
    PublicKey key, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount)
{
    // derive a broadcast key based on partition
    BroadcastKey bKey;
//    printf("Partition from %d to %d ... \n", 0, idCount - 1);

    //for(int i=0; i<idCount; i++)
    //    printf("%s\n", idSet[i]);
    decrypt_user(&bKey, partCipher, key, ikey, id, idSet, idCount);
//    printf("KEY : "); print_hex(bKey, 32);
    // decrypt the encrypted group key by partition broadcast key
    unsigned char iv[16];
    memcpy(iv, partEncKey + 32, 16);
//    print_hex(iv, 16);
    unsigned char pKey[32];
    memcpy(pKey, partEncKey, 32);
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, bKey, iv);
    EVP_DecryptUpdate(ctx, *gKey, &len, pKey, 32);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, (*gKey) + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // cleanup?
}
