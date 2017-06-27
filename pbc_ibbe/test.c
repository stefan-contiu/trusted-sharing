
//#define PBC_DEBUG


#include "ibbe.h"
#include <stdio.h>
#include <time.h>

char S[MAX_RECEIVER][MAX_STRING_LENGTH];
char Attacker[MAX_STRING_LENGTH] = "wrongdecrypt@mail.com";

int main(int argc, char** argv)
{
    printf("IBBE DEMO : \n");
    int i;
    clock_t time1, time2;
    for (i = 0; i < MAX_RECEIVER; i++)
    {
        sprintf(S[i], "test%d@mail.com", i+1);
        printf("User : %s\n", S[i]);
    }

    PublicKey pubkey;
    PrivateKey prvkey;
    IdentityKey idkey[MAX_RECEIVER+1];
    Setup(&pubkey, &prvkey, argc, argv);
/*
    {
        printf("--------------------\n");
        printf("Master publick key:\n");
        element_printf("w = %B\n", pubkey.w);
        element_printf("v = %B\n", pubkey.v);
        for (i = 0; i < MAX_RECEIVER; i++){
            element_printf("h[%d] = %B\n", i, pubkey.h[i]);
        }
        printf("--------------------\n");
    }
    {
        printf("--------------------\n");
        printf("Master secret key:\n");
        element_printf("g = %B\n", prvkey.g);
        element_printf("r = %B\n", prvkey.r);
        printf("--------------------\n");
    }
    //{
    //    printf("--------------------\n");
    //    printf("Identity key:\n");
    //    element_printf("idkey = %B\n", idkey);
    //    printf("--------------------\n");
    //}
*/
    mpz_t message;
    Plain plain;
    Cypher cypher;
    mpz_init(message);
    mpz_set_ui(message, 666);
    printf("--------Encryption START --------\n");
    time1 = clock();
    Encrypt(message, &cypher, pubkey, (char**)S, MAX_RECEIVER);
    time2 = clock();
    {
        //printf("--------------------\n");
    //    printf("Cypher text :\n");
    //    element_printf("c1 = %B\n", cypher.c1);
    //    element_printf("c2 = %B\n", cypher.c2);
    //    element_printf("c3 = %B\n", cypher.c3);
        //printf("--------------------\n");
    }
    printf("--------Encryption END --------\n\n");
    printf("@time cost: %lfms\n\n ", 1000.0*(time2-time1)/CLOCKS_PER_SEC);

    for (i = 0; i < MAX_RECEIVER; i++)
    {
        Extract(prvkey, idkey[i], S[i]);
        printf("--------Decryption S%d--------\n", i+1);
        time1 = clock();
        if (Decrypt(&plain, cypher, pubkey, idkey[i], S[i], (char**)S, MAX_RECEIVER))
        {
            printf("ID: %s is not a member of the receiver set.\n", S[i]);
            break;
        }
        {

            time2 = clock();
            //printf("--------------------\n");
            printf("Plain text :\n");
            element_printf("m = %B\n", plain);
            //printf("--------------------\n");
        }
        printf("--------Decryption S%d--------\n", i+1);
        printf("@time cost: %lfms\n\n ", 1000.0*(time2-time1)/CLOCKS_PER_SEC);
        //getchar();
    }


    return 0;
    {
        Extract(prvkey, idkey[MAX_RECEIVER+1-1], Attacker);
        printf("--------BAD Decryption--------\n");
        if (Decrypt(&plain, cypher, pubkey, idkey[MAX_RECEIVER+1-1], S[2], (char**)S, MAX_RECEIVER))
        {
            printf("ID: %s is not a member of the receiver set.\n", S[i]);

        }
        else
        {
            //printf("--------------------\n");
            printf("Plain text :\n");
            element_printf("m = %B\n", plain);
            //printf("--------------------\n");
        }
        printf("--------BAD Decryption--------\n");
        //getchar();
    }


    //getchar();
    return 0;
}
