#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stddef.h>
#include <stdint.h>

/*
 * Fault-tolerant heap allocator interface.
 *
 * The allocator manages a caller-provided contiguous heap region.
 * It provides guarded allocation, deallocation and bounded
 * read/write operations with basic soft-error detection.
 *
 * Blocks are tracked using an explicit free list and carry metadata
 * such as size, flags and mirrored fields to detect corruption.
 */

 /* Flags used by allocator to describe block state. */
#define BLOCK_IS_USED         0x1
#define BLOCK_IS_PREV_FREE    0x2
#define BLOCK_IS_QUARANTINED  0x4

/* Mask to strip out the flag bits from size_and_flags. */
#define FLAGS_MASK (BLOCK_IS_USED | BLOCK_IS_PREV_FREE | BLOCK_IS_QUARANTINED)

/*
 * Simplified student-style memory block header:
 *  - Keep mirrored fields for basic integrity checking.
 *  - Remove metadata_checksum (not used in this allocator).
 *  - Keep explicit free-list pointers (doubly-linked list).
 *  - Keep padding unchanged to preserve alignment and struct size.
 */
typedef struct memory_block_header {
    size_t size_and_flags;
    size_t size_and_flags_mirror;

    size_t prev_phys_size;
    size_t prev_phys_size_mirror;

    /* metadata_checksum removed */

    struct memory_block_header* next_free_block;
    struct memory_block_header* prev_free_block;

    /* Padding to keep header size and alignment consistent. */
    uint8_t padding[4];
} memory_block_header_t;

/*
 * Helper used by tests and internal logic.
 *
 * Given a payload pointer, compute the address of the corresponding
 * memory_block_header_t if it lies inside the managed heap.
 * Returns NULL for invalid / out-of-range pointers.
 */
memory_block_header_t* get_header_from_payload(void* ptr);

/*
 * mm_init(heap, heap_size)
 *
 * Initialise the allocator to manage the memory region [heap, heap+heap_size).
 * The allocator will place its internal control block and an initial free block
 * inside this region.
 *
 * Returns:
 *   0  on success;
 *  -1  if the heap pointer or size is invalid.
 */
int mm_init(uint8_t* heap, size_t heap_size);

/*
 * mm_malloc(size)
 *
 * Allocate at least 'size' bytes of usable payload.
 * On success, returns a pointer to the payload region; on failure, returns NULL.
 *
 * The allocator may return NULL if:
 *   - the heap has not been initialised;
 *   - the free list contains no suitable block;
 *   - integrity checks detect corruption and the system moves to fail-stop mode.
 */
void* mm_malloc(size_t size);

/*
 * mm_free(ptr)
 *
 * Free a block previously returned by mm_malloc/mm_realloc.
 * The allocator validates the header and canary, performs quarantine on
 * corrupted or double-freed blocks, and coalesces with neighbouring free
 * blocks where possible.
 *
 * Passing NULL is a no-op.
 */
void mm_free(void* ptr);

/*
 * mm_read(ptr, offset, buf, len)
 *
 * Safely copy 'len' bytes from the payload of an allocated block into 'buf',
 * starting at byte offset 'offset'.
 *
 * Returns:
 *   number of bytes copied on success;
 *  -1 on any error (invalid pointer, out-of-bounds, failed integrity checks).
 */
int mm_read(void* ptr, size_t offset, void* buf, size_t len);

/*
 * mm_write(ptr, offset, src, len)
 *
 * Safely copy 'len' bytes from 'src' into the payload of an allocated block,
 * starting at byte offset 'offset'.
 *
 * Returns:
 *   number of bytes written on success;
 *  -1 on any error (invalid pointer, out-of-bounds, failed integrity checks).
 *
 * The canary is automatically updated after a successful write.
 */
int mm_write(void* ptr, size_t offset, const void* src, size_t len);

/*
 * mm_realloc(ptr, new_size)
 *
 * Change the size of an existing allocation while preserving data:
 *   - If ptr == NULL and new_size > 0, behaves like mm_malloc(new_size).
 *   - If new_size == 0, behaves like mm_free(ptr) and returns NULL.
 *   - Otherwise, validates the block; if the current payload is large enough
 *     it is reused in-place, otherwise a new block is allocated and data is
 *     copied before freeing the old block.
 *
 * On failure, the original block remains valid and unchanged.
 */
void* mm_realloc(void* ptr, size_t new_size);

#endif /* ALLOCATOR_H */
