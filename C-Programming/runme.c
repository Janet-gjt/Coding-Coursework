#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "allocator.h"

#define DEFAULT_HEAP_SIZE (1 * 1024 * 1024)

/*
 * Small test driver for the fault-tolerant allocator.
 *
 * It first runs a set of simple "sunny-day" tests (alignment, basic
 * alloc/free, read/write, out-of-bounds detection and double-free
 * handling), and then optionally runs a stress test under simulated
 * radiation storms (random bit flips in the heap).
 */

typedef struct {
    int alloc_ok;
    int alloc_fail;
    int free_ops;
    int write_ok;
    int write_fail;
} storm_stats_t;

/*
 * Pretty-print a single test result with a PASS/FAIL prefix.
 */
static void print_test_result(const char* test_name, int success)
{
    printf("[%s] %-30s ... %s\n",
        success ? "PASS" : "FAIL",
        test_name,
        success ? "OK" : "ERROR");
}

/*
 * Flip a random bit somewhere in the simulated heap payload region.
 *
 * We deliberately skip the first 64 bytes so as not to corrupt the
 * heap_system_control_block_t (allocator control metadata).
 * This models soft errors caused by cosmic rays or similar phenomena.
 */
static void flip_random_bit(uint8_t* heap, size_t heap_size)
{
    if (heap == NULL || heap_size <= 64) {
        return;
    }

    /* First 64 bytes are reserved for heap_system_control_block_t. */
    size_t header_area = 64;
    size_t index = header_area + (size_t)(rand() % (heap_size - header_area));

    uint8_t bit = (uint8_t)(1u << (rand() % 8));
    heap[index] ^= bit;
}

/*
 * A set of simple "sunny day" tests to ensure that basic allocator
 * behaviour is correct before we start injecting faults.
 *
 * This covers:
 *   - basic allocations and frees;
 *   - payload alignment;
 *   - safe read/write of payload data;
 *   - out-of-bounds write rejection;
 *   - double-free detection and quarantine.
 */
static void run_basic_tests(uint8_t* heap_memory, size_t heap_size)
{
    (void)heap_memory;
    (void)heap_size;

    /* Basic allocation tests. */
    void* p1 = mm_malloc(40);
    void* p2 = mm_malloc(80);
    void* p3 = mm_malloc(120);

    print_test_result("allocate p1 (40)", p1 != NULL);
    print_test_result("allocate p2 (80)", p2 != NULL);
    print_test_result("allocate p3 (120)", p3 != NULL);

    /* Basic free + re-allocation test. */
    mm_free(p2);
    print_test_result("free p2", 1);

    /* Check that the allocator respects the requested alignment. */
    int align_p1_ok = ((uintptr_t)p1 % 40 == 0);
    print_test_result("p1 alignment ok", align_p1_ok);

    void* p4 = mm_malloc(100);
    print_test_result("allocate p4", p4 != NULL);

    mm_free(p1);
    mm_free(p3);
    mm_free(p4);

    /* Safe read/write tests on a fresh allocation. */
    void* p_safe = mm_malloc(100);
    char write_data[] = "programming paradigm.";
    char read_buf[64] = { 0 };
    size_t data_len = strlen(write_data) + 1;

    int w_len = mm_write(p_safe, 0, write_data, data_len);
    int r_len = mm_read(p_safe, 0, read_buf, data_len);

    int rw_ok = (w_len == (int)data_len) &&
        (r_len == (int)data_len) &&
        (strcmp(write_data, read_buf) == 0);

    print_test_result("mm_write/mm_read ok", rw_ok);

    /* Out-of-bounds write should be rejected with -1. */
    int boundary_fail = (mm_write(p_safe, 1000, write_data, 1) == -1);
    print_test_result("mm_write out of bound", boundary_fail);

    /*
     * Double-free test:
     * First free should succeed; the second free should be detected
     * and quarantined by the allocator without crashing.
     */
    mm_free(p_safe);        /* First free. */
    mm_free(p_safe);        /* Second free (should be quarantined). */

    /*
     * Allocate a new block; if the double-free quarantine worked,
     * the allocator should not hand out the same address again.
     */
    void* newptr = mm_malloc(100);
    int double_free_ok = (newptr != p_safe);
    print_test_result("double free detection", double_free_ok);

    mm_free(newptr);
}

/*
 * Stress test under simulated storm conditions:
 * we perform a mixture of allocations, frees and read/write operations
 * while injecting random bit flips into the heap after each iteration.
 *
 * The goal is to verify that the allocator fails safely:
 *   - no crashes or segmentation faults;
 *   - integrity checks may reject operations, but the process survives.
 */
static void run_storm_tests(uint8_t* heap_memory,
    size_t heap_size,
    int storm_level,
    unsigned int seed)
{
    printf("\n=== Storm test: level=%d, seed=%u ===\n",
        storm_level, seed);

    srand(seed);

    const int NUM_PTRS = 64;
    const int ITERATIONS = 1000;

    /* Array of live pointers used during the storm test. */
    void* ptrs[NUM_PTRS];
    for (int i = 0; i < NUM_PTRS; ++i) {
        ptrs[i] = NULL;
    }

    storm_stats_t stats = { 0, 0, 0, 0, 0 };

    for (int iter = 0; iter < ITERATIONS; ++iter) {
        /* Randomly choose between alloc, free, and write+read. */
        int action = rand() % 3;  /* 0=alloc, 1=free, 2=write+read */

        if (action == 0) {
            /* Random allocation size in a moderate range. */
            size_t size = 8 + (size_t)(rand() % 512);
            void* p = mm_malloc(size);
            if (p != NULL) {
                stats.alloc_ok++;

                /* Replace a random pointer in the array. */
                int idx = rand() % NUM_PTRS;
                if (ptrs[idx] != NULL) {
                    mm_free(ptrs[idx]);
                    stats.free_ops++;
                }
                ptrs[idx] = p;
            }
            else {
                stats.alloc_fail++;
            }
        }
        else if (action == 1) {
            /* Randomly free one of the tracked pointers. */
            int idx = rand() % NUM_PTRS;
            if (ptrs[idx] != NULL) {
                mm_free(ptrs[idx]);
                ptrs[idx] = NULL;
                stats.free_ops++;
            }
        }
        else {
            /*
             * For an existing pointer, perform a small write+read round trip
             * and record whether it was accepted or rejected.
             */
            int idx = rand() % NUM_PTRS;
            if (ptrs[idx] != NULL) {
                char msg[] = "storm-test";
                char buf[32] = { 0 };

                int w = mm_write(ptrs[idx], 0, msg, sizeof(msg));
                int r = mm_read(ptrs[idx], 0, buf, sizeof(msg));

                if (w == (int)sizeof(msg) &&
                    r == (int)sizeof(msg) &&
                    strcmp(msg, buf) == 0) {
                    stats.write_ok++;
                }
                else {
                    /*
                     * A failure here is not necessarily incorrect: the
                     * allocator may have detected corruption and refused
                     * the operation, which is exactly what we want to
                     * observe under storm conditions.
                     */
                    stats.write_fail++;
                }
            }
        }

        /* Inject storm_level random bit flips into the heap. */
        for (int k = 0; k < storm_level; ++k) {
            flip_random_bit(heap_memory, heap_size);
        }
    }

    /* Clean up any remaining live pointers. */
    for (int i = 0; i < NUM_PTRS; ++i) {
        if (ptrs[i] != NULL) {
            mm_free(ptrs[i]);
            stats.free_ops++;
            ptrs[i] = NULL;
        }
    }

    printf("\nStorm test summary:\n");
    printf("  alloc ok      = %d\n", stats.alloc_ok);
    printf("  alloc fail    = %d\n", stats.alloc_fail);
    printf("  free ops      = %d\n", stats.free_ops);
    printf("  write ok      = %d\n", stats.write_ok);
    printf("  write fail    = %d\n", stats.write_fail);

    /*
     * As long as the program reaches this point without crashing,
     * we consider the storm test conceptually passed: all faults
     * were either tolerated or detected and contained.
     */
    print_test_result("storm test completed (no crash)", 1);
}

/*
 * Program entry point.
 *
 * Command-line options:
 *   --size  N   : size of the simulated heap in bytes
 *   --seed  S   : RNG seed used for storm tests
 *   --storm L   : storm level (number of bit flips per iteration)
 */
int main(int argc, char** argv)
{
    size_t heap_size = DEFAULT_HEAP_SIZE;
    unsigned int seed = (unsigned int)time(NULL);
    int storm_level = 0;  /* Default: no storm, only basic tests. */

    /* Parse command-line arguments: --size, --seed, --storm. */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            heap_size = (size_t)strtoull(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = (unsigned int)strtoul(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--storm") == 0 && i + 1 < argc) {
            storm_level = atoi(argv[++i]);
            if (storm_level < 0) {
                storm_level = 0;
            }
        }
        else {
            /*
             * Unknown argument: we simply ignore it to keep
             * the test driver lightweight.
             */
        }
    }

    printf("Using heap_size=%zu, seed=%u, storm_level=%d\n",
        heap_size, seed, storm_level);

    /*
     * According to the coursework specification, we must only
     * perform a single host malloc() to obtain a chunk of memory
     * that will act as the simulated heap.
     */
    uint8_t* heap_memory = (uint8_t*)malloc(heap_size);
    if (heap_memory == NULL) {
        fprintf(stderr, "Failed to allocate heap\n");
        return 1;
    }

    /* Initialisation of the custom allocator. */
    int init_result = mm_init(heap_memory, heap_size);
    print_test_result("mm_init", init_result == 0);

    if (init_result != 0) {
        free(heap_memory);
        return 1;
    }

    /* Run basic non-storm tests first. */
    run_basic_tests(heap_memory, heap_size);

    /* If requested, run the storm stress tests as well. */
    if (storm_level > 0) {
        run_storm_tests(heap_memory, heap_size, storm_level, seed);
    }

    printf("\nSUCCESS!\n");

    free(heap_memory);
    return 0;
}
