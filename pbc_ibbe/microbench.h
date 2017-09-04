#ifndef MICROBENCH_H
#define MICROBENCH_H

#include <time.h>

// TODO : optimal value is 17. Keep 10 for testing.
#define MICRO_POINTS 10

//#define MICRO_CREATE
#define MICRO_ADD
#define MICRO_REMOVE

#define start_clock clock_gettime(CLOCK_MONOTONIC, &start);
#define end_clock(m) clock_gettime(CLOCK_MONOTONIC, &finish); double m = (finish.tv_sec - start.tv_sec) + ((finish.tv_nsec - start.tv_nsec) / 1000000000.0);


// MICROBENCH_H
#endif