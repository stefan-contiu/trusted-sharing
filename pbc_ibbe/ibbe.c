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
#include <openssl/sha.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

pairing_t pairing;

int setup_sgx_safe(PublicKey *puk, ShortPublicKey *spuk, MasterSecretKey *msk, int argc, char** argv)
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
        hRec = (element_t*)malloc(sizeof(element_t) * (MAX_RECEIVER+2));
        mpz_t n;
        mpz_init(n);
        for (i = 0; i <= MAX_RECEIVER; i++)
        {
            element_init_G2(hRec[i], pairing);
            mpz_set_ui(n, (unsigned int)i);
            element_pow_mpz(temp1, gamma, n);
            element_pow_zn(hRec[i], h, temp1);
        }
        mpz_clear(n);

        // Most likely these commented lines are useless, will keep them until
        // all tests w/ and w/out SGX are finalized, then remove!
        /*h ^ r ^ (-1)*/
        //element_init_G1(hRec[i], pairing);
        //element_invert(temp1, r);
        //element_pow_zn(hRec[i], h, temp1);
        // ---- end commented lines

        puk->h = hRec;
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
        printf("Pub key element size (bytes): %d\n", hlen);
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
    element_t c1, c2;
    element_t product;
    element_t hash;

    element_init_Zr(k, pairing);
    element_init_G1(c1, pairing);
    element_init_G2(c2, pairing);
    element_random(k);

    // compute C1
    {
        element_pow_zn(c1, pubKey.w, k);
        element_invert(c1, c1);
        //element_printf("C1 : %B\n", c1);
    }

    // compute C2
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

        // multiply whole product by k
        element_mul(product, product, k);

        // raise h to product
        element_pow_zn(c2, pubKey.h, product);
        //element_printf("C2 : %B\n", c2);
    }

    // compute BroadcastKey
    {
        element_t key_element;
        element_init_GT(key_element, pairing);
        element_pow_zn(key_element, pubKey.v, k);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(key_element);
        unsigned char* key_element_bytes = malloc(generated_key_length);
        element_to_bytes(key_element_bytes, key_element);
        SHA256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    element_init_G1(cipher->c1, pairing);
    element_init_G1(cipher->c2, pairing);
    element_set(cipher->c1, c1);
    element_set(cipher->c2, c2);

    element_clear(k);
    element_clear(c1);
    element_clear(c2);
    element_clear(hash);
    element_clear(product);

    return 0;
}

int decrypt_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
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
        unsigned char* key_element_bytes = malloc(generated_key_length);
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
        /*polynominal multiplication */
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
            element_set(htemp1, key.h[MAX_RECEIVER+1]);
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
    unsigned char* key_element_bytes = malloc(generated_key_length);
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

void *exponentiate_by_partition(void *pargs)
{
    struct exp_part_struct *args = (struct exp_part_struct *)pargs;
//    printf("PART START : %d\n", args->start);
//    printf("PART END   : %d\n", args->end);

    /* old style exponentiation */
    element_t thread_temp2;

    element_t* ptemp = (element_t*) malloc(sizeof(element_t));
    element_init_G1(*ptemp, pairing);
    element_set1(*ptemp);

    element_init_G1(thread_temp2, pairing);
    //element_set1(thread_temp1);

    int i;
    int max = 0;
    for (i = args->start; i <= args->end - 3; i+=3)
    {
        element_pow3_zn(thread_temp2,
            args->key.h[i], args->polyA[i],
            args->key.h[i+1], args->polyA[i+1],
            args->key.h[i+2], args->polyA[i+2]);
        element_mul(*ptemp, *ptemp, thread_temp2);
        max = i > max ? i : max;
    }
    // exponentiate and multiply any leftovers
    if (i <= args->end)
    {
        for (int j = i; j <= args->end; j++)
        {
            element_pow_zn(thread_temp2, args->key.h[j], args->polyA[j]);
            element_mul(*ptemp, *ptemp, thread_temp2);
            max = i > max ? i : max;
        }
    }

    printf("Max %d\n", max);
    pthread_exit(ptemp);
    return (void*) ptemp;
}

int decrypt_user(int sw, BroadcastKey* bKey, Ciphertext cipher, PublicKey key, UserPrivateKey ikey, char* id, char idSet[][MAX_STRING_LENGTH], int idCount)
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

        // I think the bellow if can be removed
        /*calculation*/
        if (idCount == 1)
        {
            /*dealing with only 1 receiver*/
            element_set(htemp1, key.h[MAX_RECEIVER+1]);
        }
        else
        {
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
            if (sw == 1)
            {
                int idNum = idCount - 2;
                int exp_per_partition = idNum / THREADS_COUNT;

                pthread_t tid[THREADS_COUNT];
                for(int thread_idx = 0; thread_idx < THREADS_COUNT; thread_idx++)
                {
                    // compute the partition of exponentiations
                    struct exp_part_struct* args= malloc (sizeof (struct exp_part_struct));
                    args->start = thread_idx * exp_per_partition;
                    args->end = args->start + exp_per_partition - 1;
                    args->key = key;
                    args->polyA = polyA;
                    if (thread_idx == THREADS_COUNT - 1)
                    {
                        args->end += 2;
                    }

                    pthread_create(&tid[thread_idx], NULL, exponentiate_by_partition, (void *)args);
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

                //element_printf("THR TEMP1 : %B\n", result);
            }
            else
            {
                for (i = 0; i < idCount-1; i++)
                {
                    element_pow_zn(htemp2, key.h[i], polyA[i+1]);
                    element_mul(htemp1, htemp1, htemp2);
                    printf("USING %d\n", i);
                }
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
    unsigned char* key_element_bytes = malloc(generated_key_length);
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


int Encrypt(Ciphertext *cipher, PublicKey key, char idSet[][MAX_STRING_LENGTH], int idNum)
{
    element_t k;
    element_t m;
    element_t c1, c2, c3;
    element_t temp1, temp2;

    element_init_GT(m, pairing);
    element_init_G1(c1, pairing);
    element_init_G1(c2, pairing);
    element_init_GT(c3, pairing);
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);

    //element_random(k);
    //element_set_mpz(m, message);

    /*compute c1 = w ^ -k*/
    {
        element_pow_zn(c1, key.w, k);
        element_invert(c1, c1);
    }

    /*compute c2 = h ^ (k * (r+H(ID)...)*/
    {
        /*polynominal multiplication */
        /***************************************/
        int i, j;
        /*
        element_t hid[idNum + 1];
        element_t polyA[idNum + 1], polyB[idNum + 1];
        */
        element_t *hid;
        element_t *polyA, *polyB;
        hid = (element_t*)malloc(sizeof(element_t) * idNum);
        polyA = (element_t*)malloc(sizeof(element_t) * (idNum+1));
        polyB = (element_t*)malloc(sizeof(element_t) * (idNum+1));

        clock_t time1, time2;

        /*initialization*/
        time1 = clock();
        for (i = 0; i < idNum+1; i++)
        {
            element_init_Zr(polyA[i], pairing);
            element_set0(polyA[i]);
            element_init_Zr(polyB[i], pairing);
            element_set0(polyB[i]);
            element_init_Zr(hid[i], pairing);
            if (i < idNum)
            {
                //printf("Receiver %d: %s\n", i+1, idSet+i*5);


                //unsigned char ibuf[] = "compute sha1";
                unsigned char obuf[20];

                //SHA1(ibuf, strlen(ibuf), obuf);
                //SHA1(idSet[i], strlen(idSet[i]), obuf);

                element_from_hash(hid[i], idSet[i], strlen(idSet[i]));
                //element_from_hash(hid[i], obuf, strlen(obuf));
                //element_random(hid[i]);
            }
        }
        time2 = clock();
        printf("@Computing hashes : %lfms\n\n ", 1000.0*(time2-time1)/CLOCKS_PER_SEC);

        /*calculation*/
        time1 = clock();
        element_set(polyA[0], hid[0]);
        element_set1(polyA[1]);
        for (i = 1; i < idNum; i++)
        {
            /*i-th polynomial*/
            /*polyA * (r + H(ID))*/
            element_set1(polyA[i+1]);
            for (j = i; j >= 1; j--)
            {
                element_mul(polyB[j], polyA[j], hid[i]);
                element_add(polyA[j], polyA[j-1], polyB[j]);
                //element_printf("%B\n", polyA[j]);
            }
            element_mul(polyA[0], polyA[0], hid[i]);
        }
        time2 = clock();
        printf("@Polynomial expansion : %lfms\n\n ", 1000.0*(time2-time1)/CLOCKS_PER_SEC);

        printf("START COUNTING ... \n");
        clock_t time_exp = clock();
        /* old style exponentiation */
        /*
        element_t old_temp1, old_temp2;
        element_init_G1(old_temp1, pairing);
        element_init_G1(old_temp2, pairing);
        element_set1(old_temp1);
        for (i = 0; i < idNum+1; i++)
        {
            element_pow_zn(old_temp2, key.h[i], polyA[i]);
            element_mul(old_temp1, old_temp1, old_temp2);
        }
        element_printf("OLD TEMP1 : %B\n", old_temp1);
        */
        /* finished old style exponentation */

        /* 3-Batch Exponentation */
/*        element_set1(temp1);
        for (i = 0; i < idNum-1; i+=3)
        {
            element_pow3_zn(temp2,
                key.h[i], polyA[i],
                key.h[i+1], polyA[i+1],
                key.h[i+2], polyA[i+2]);
            element_mul(temp1, temp1, temp2);
        }
        // exponentiate and multiply any leftovers
        if (i < idNum + 1)
        {
            for (j = i; j < idNum + 1; j++)
            {
                element_pow_zn(temp2, key.h[j], polyA[j]);
                element_mul(temp1, temp1, temp2);
            }
        }
        element_printf("NEW TEMP1 : %B\n", temp1);
*/

        /* Multithreaded exponentation */
/*
        if (idNum > 299)
        {
            // it's worth doing parallel once groups get some users
            int THREADS_COUNT = 8;
            int exp_per_partition = idNum / THREADS_COUNT;

            pthread_t tid[THREADS_COUNT];
            for(int thread_idx = 0; thread_idx < THREADS_COUNT; thread_idx++)
            {
                // compute the partition of exponentiations
                struct exp_part_struct* args= malloc (sizeof (struct exp_part_struct));
                args->start = thread_idx * exp_per_partition;
                args->end = args->start + exp_per_partition - 1;
                args->key = key;
                args->polyA = polyA;
                if (thread_idx == THREADS_COUNT - 1)
                {
                    args->end++;
                }

                pthread_create(&tid[thread_idx], NULL, exponentiate_by_partition, (void *)args);
            }

            element_t result;
            element_init_G1(result, pairing);
            element_set1(result);
            // wait that threads are complete
            for(int thread_idx = 0; thread_idx < THREADS_COUNT; thread_idx++)
            {
                void* partition_result;
                pthread_join(tid[thread_idx], &partition_result);
                if (partition_result == NULL)
                {
                    printf("NULL PASSED !!!!\n");
                }
                element_mul(temp1, temp1, *(element_t*)partition_result);
            }

            //element_printf("THR TEMP1 : %B\n", result);
        }

        clock_t time_exp_end = clock();
        printf("@linear exponentiations : %lu\n ", time_exp_end - time_exp);
*/
        element_pow_zn(c2, temp1, k);
    //    printf("c2 second half computed !!!!\n");

        /*
        free(hid);
        free(polyA);
        free(polyB);
        */
    }

    /*calculate c3 = v^k * m*/
    {
        element_pow_zn(c3, key.v, k);
        element_mul(c3, c3, m);
    }

    element_init_G1(cipher->c1, pairing);
    element_init_G1(cipher->c2, pairing);
    //element_init_GT(cipher->c3, pairing);
    element_set(cipher->c1, c1);
    element_set(cipher->c2, c2);
    //element_set(cipher->c3, c3);

    element_clear(k);
    element_clear(m);
    element_clear(temp1);
    element_clear(temp2);

    return 0;
}
