#ifndef MICROBENCH_H
#define MICROBENCH_H

#include <time.h>
#include "admin_api.h"
#include "hybrid_api.h"
#include "tests.h"

// TODO : optimal value is 17. Keep 10 for testing.
#define MICRO_POINTS 10

#define MICRO_CREATE
#define MICRO_ADD
#define MICRO_REMOVE
#define MICRO_DECRYPT

#define start_clock clock_gettime(CLOCK_MONOTONIC, &start);
#define end_clock(m) clock_gettime(CLOCK_MONOTONIC, &finish); double m = (finish.tv_sec - start.tv_sec) + ((finish.tv_nsec - start.tv_nsec) / 1000000000.0);

static inline void microbenchmarks()
{
    SpibbeApi* spibbeAdmin = new SpibbeApi("master", new RedisCloud());
    HybridApi* hybridAdmin = new HybridApi("master", new RedisCloud());

/*
    micro_create_group(spibbeAdmin);
    micro_create_group(hybridAdmin);
  
    micro_add_user(spibbeAdmin);
    micro_add_user(hybridAdmin);
    
    micro_remove_user(spibbeAdmin);
    micro_remove_user(hybridAdmin);
*/

    std::string u = "test0@mail.com";
    SpibbeUserApi* spibbeUser = new SpibbeUserApi(u, new RedisCloud(), spibbeAdmin);
    HybridUserApi* hybridUser = new HybridUserApi(u, new RedisCloud());
    micro_decrypt_key(spibbeAdmin, spibbeUser);
    micro_decrypt_key(hybridAdmin, hybridUser);
}


// MICROBENCH_H
#endif