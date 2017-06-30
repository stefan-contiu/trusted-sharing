#include "ibbe.h"
#include <openssl/sha.h>


pairing_t pairing;

int Setup(PublicKey *puk, PrivateKey *prk, int argc, char** argv)
{
    int i;
    element_t g, h;
    element_t w, v;
    element_t r;
    element_t temp1;
    element_t *hRec;

    /*init a pairing using system params*/
    srand(time(NULL));
    pbc_random_set_deterministic(rand());//����������
    pbc_demo_pairing_init(pairing, argc, argv);
    printf("Pairing initialized ...\n");

    element_init_G1(g, pairing);
    element_init_G1(h, pairing);
    element_init_G1(w, pairing);
    element_init_GT(v, pairing);
    element_init_Zr(r, pairing);
    element_init_Zr(temp1, pairing);
    printf("Pairing initialized ...\n");

    /*pick 2 generators in G*/
    element_random(g);
    element_random(h);
    /*pick random value r in Zp*/
    element_random(r);
    printf("Pairing initialized ...\n");


    element_pow_zn(w, g, r);    //w = g ^ r
    element_pairing(v, g, h);   //v = e(g, h)
    printf("Last    Pairing initialized ...\n");

    element_pp_t g_pp;
    element_pp_init(g_pp, r);
    printf("Got here ...\n");

    hRec = (element_t*)malloc(sizeof(element_t) * (MAX_RECEIVER+2));
    mpz_t n;
    mpz_init(n);
    for (i = 0; i <= MAX_RECEIVER; i++)
    {
        element_init_G1(hRec[i], pairing);
        mpz_set_ui(n, (unsigned int)i);
        element_pow_mpz(temp1, r, n);
        //element_printf("%B\n", h);
        //element_printf("%B\n", temp1);
        element_pow_zn(hRec[i], h, temp1);
        //element_printf("%B\n", hRec[i]);
        //element_pp_pow_zn(hRec[i], temp1, g_pp);
    }
    /*h ^ r ^ (-1)*/
    element_init_G1(hRec[i], pairing);
    element_invert(temp1, r);
    element_pow_zn(hRec[i], h, temp1);
    /*cleaning*/
    mpz_clear(n);
    element_pp_clear(g_pp);

    puk->h = hRec;
    element_init_G1(puk->w, pairing);
    element_init_GT(puk->v, pairing);
    element_set(puk->w, w);
    element_set(puk->v, v);

    element_init_G1(prk->g, pairing);
    element_init_Zr(prk->r, pairing);
    element_set(prk->g, g);
    element_set(prk->r, r);

    element_clear(h);
    element_clear(temp1);

    return 0;
}

int Extract(PrivateKey key, IdentityKey idkey, char* id)
{
    element_t hid;
    IdentityKey ikey;

    element_init_Zr(hid, pairing);
    element_init_G1(ikey, pairing);

    /***************************************/
    /*how do we hash ID into an element in Zp?*/
    //hash(hid, id);
    {
        printf("--------------------\n");
        printf("Generating key for :");
        printf("%s\n", id);
        printf("--------------------\n");
    }
    element_from_hash(hid, id, strlen(id));
    /***************************************/

    /*calculate SK = g ^ ((r + H(ID)) ^ -1)*/
    element_add(hid, hid, key.r);
    element_invert(hid, hid);
    element_pow_zn(ikey, key.g, hid);

    element_clear(hid);

    element_init_G1(idkey, pairing);
    element_set(idkey, ikey);

    return 0;
}

int DestroySK(IdentityKey ikey)
{
    element_clear(ikey);
    return 0;
}

int Encrypt(mpz_t message, Cipher *cipher, PublicKey key, char idSet[][MAX_STRING_LENGTH], int idNum)
{
    element_t k;
    element_t m;
    element_t c1, c2, c3;
    element_t temp1, temp2;

    element_init_Zr(k, pairing);
    element_init_GT(m, pairing);
    element_init_G1(c1, pairing);
    element_init_G1(c2, pairing);
    element_init_GT(c3, pairing);
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);

    element_random(k);
    //element_set_mpz(m, message);
    element_random(m);
    {
        printf("--------------------\n");
        printf("Plain text :\n");
        element_printf("m = %B\n", m);
        printf("--------------------\n");
    }

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
        /*initialization*/
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
                SHA1(idSet[i], strlen(idSet[i]), obuf);

                //element_from_hash(hid[i], idSet[i], strlen(idSet[i]));
                element_from_hash(hid[i], obuf, strlen(obuf));
                //element_random(hid[i]);

/*
                int ii;
                char* buf_str = (char*) malloc (2*20 + 1);
                char* buf_ptr = buf_str;
                for (ii = 0; ii < 20; ii++)
                {
                    buf_ptr += sprintf(buf_ptr, "%02X", obuf[ii]);
                }
                //sprintf(buf_ptr,"\n");
                *(buf_ptr + 1) = '\0';
                printf("MAGIC : %s\n", buf_str);



                //printf("SHA : %s\n", obuf);

                mpz_t hash_mpz;
                mpz_init(hash_mpz);
                //mpz_set_ui(message, 666);
                mpz_set_str(hash_mpz, buf_str, 16);
        //        gmp_printf("hashed mpz= %Zd\n", hash_mpz);
                element_set_mpz(hid[i], hash_mpz);

                //int req_bytes = pairing_length_in_bytes_Zr(pairing);
                //printf("REQUIRED BYTES for Zp : %d\n", req_bytes);


                //
                element_printf("%B\n", hid[i]);

                //element_from_bytes(hid[i], obuf);
*/
            }
        }

    //    printf("c2 was init !!!!\n");

        /*calculation*/
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
    //    printf("c2 half computed !!!!\n");

        element_set1(temp1);
    //    printf("no crash 1 !!!!\n");

    // TODO : the loop needs to be fixed to work with non-multiple of 3

        for (i = 0; i < idNum-1; i+=3)
//        for (i = 0; i < idNum+1; i++)
        {
            //printf("no crash loop %d !!!!\n", i);
            //element_printf("temp2 : %B\n", temp2);
            //element_printf("key h i : %B\n", key.h[i]);
            //element_printf("poly : %B\n", polyA[i]);


            element_pow3_zn(temp2, key.h[i], polyA[i], key.h[i+1], polyA[i+1], key.h[i+2], polyA[i+2]);
            //element_pow2_zn(temp2, key.h[i], polyA[i], key.h[i+1], polyA[i+1]);
            // old way:
//            element_pow_zn(temp2, key.h[i], polyA[i]);
            element_mul(temp1, temp1, temp2);
        }
    //    printf("no crash 3 !!!!\n");

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
    element_init_GT(cipher->c3, pairing);
    element_set(cipher->c1, c1);
    element_set(cipher->c2, c2);
    element_set(cipher->c3, c3);

    element_clear(k);
    element_clear(m);
    element_clear(temp1);
    element_clear(temp2);

    return 0;
}


int Decrypt(Plain *plain, Cipher cipher, PublicKey key, IdentityKey ikey, char* id, char idSet[][MAX_STRING_LENGTH], int idNum)
{
    int i, j;
    int mark = 1;
    char **SubSet;

    for (i = 0; i < idNum; i++)
    {
        /*check if id is a memeber of idSet*/
        if (strcmp(id, idSet[i]) == 0)
        {
            mark = 0;
            break;
        }
    }
    if (mark)
    {
        printf("%s is not a sub member of IDSet\n", id);
        return 1;
    }
    mark = i;
    /*generate SubSet which excludes id*/
    SubSet = (char**)malloc(sizeof(char*) * (idNum - 1));
    for (i = 0, j = 0; i < idNum; i++)
    {
        if (i == mark)
            continue;
        SubSet[j] = (char*)malloc(sizeof(char) * MAX_STRING_LENGTH);
        memcpy(SubSet[j], idSet[i], MAX_STRING_LENGTH);
        //printf("%dth exclusive member: %s\n", j+1, SubSet[j]);
        j++;
    }

    element_t htemp1, htemp2;
    element_t temp1, temp2;
    element_t ztemp;

    element_init_G1(htemp1, pairing);
    element_init_G1(htemp2, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_Zr(ztemp, pairing);
    element_init_GT(*plain, pairing);

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
                element_from_hash(hid[i], SubSet[i], strlen(SubSet[i]));
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
                // TODO : uncomment this line
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

    // todo : this would have to be fixed as it assumes that idNum-1 is the
    // element we exlude from the set, or not?
    element_set1(ztemp);
    for (i = 0; i < idNum - 1; i++)
    {
        element_mul(ztemp, ztemp, hid[i]);
    }
    element_invert(ztemp, ztemp);

    /*K*/
    element_pow_zn(temp1, temp1, ztemp);

    element_div(*plain, cipher.c3, temp1);

    //free(hid);
    element_clear(htemp1);
    element_clear(htemp2);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(ztemp);

    return 0;
}
