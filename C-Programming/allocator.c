#include "allocator.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ALIGNMENT_SIZE 40
#define BLOCK_IS_USED 0x1
#define BLOCK_IS_PREV_FREE 0x2
#define BLOCK_IS_QUARANTINED 0x4
#define FLAGS_MASK (BLOCK_IS_USED | BLOCK_IS_PREV_FREE | BLOCK_IS_QUARANTINED)
#define GET_ACTUAL_SIZE(head_ptr) \
    ((head_ptr)->size_and_flags & ~(FLAGS_MASK))
#define MIN_SPLIT_THRESHOLD (sizeof(memory_block_header_t))
#define GET_SYSTEM_CONTROL(heap_ptr) \
    ((heap_system_control_block_t *)(heap_ptr))
#define PAYLOAD_CANARY_VALUE 0xDEADBEEFDEADBEEFULL
#define PAYLOAD_CANARY_SIZE (sizeof(uint64_t))

const uint8_t UNUSED_SIGNATURE[] = { 0xA5, 0x5A, 0x1E, 0xED, 0x07 };
const size_t SIGNATURE_LENGTH = 5;

static uint8_t* heap_base_address = NULL;
static size_t heap_capacity = 0;

typedef struct heap_system_control_block {
    uint8_t* system_start_ptr;
    size_t total_memory_capacity;
    struct memory_block_header* master_free_list;
    uint32_t system_integrity_hash;
    uint8_t alignment_padding[36];
} heap_system_control_block_t;

/* Forward declarations for internal helpers. */
static void insert_into_free_list(
    heap_system_control_block_t* control,
    memory_block_header_t* block);
static void remove_from_free_list(
    heap_system_control_block_t* control,
    memory_block_header_t* block);
static int validate_block_integrity(memory_block_header_t* block);
static void update_block_checksum(memory_block_header_t* block);
static void update_next_prev_size(
    heap_system_control_block_t* control,
    memory_block_header_t* current);
static memory_block_header_t* safe_next_free(
    heap_system_control_block_t* control,
    memory_block_header_t* b);

static uint8_t* get_payload_from_header(memory_block_header_t* header) {
    return (uint8_t*)header + sizeof(memory_block_header_t);
}

/*
 * Check whether a pointer points to a plausible block header inside
 * the managed heap region and that its size looks sane and aligned.
 */
static int is_pointer_in_heap_and_aligned(
    void* p,
    heap_system_control_block_t* control)
{
    (void)control;

    if (p == NULL || heap_base_address == NULL || heap_capacity == 0) {
        return 0;
    }

    uint8_t* heap_start =
        heap_base_address + sizeof(heap_system_control_block_t);
    uint8_t* heap_end = heap_base_address + heap_capacity;

    uint8_t* ptr = (uint8_t*)p;
    if (ptr < heap_start) {
        return 0;
    }
    if ((uintptr_t)ptr + sizeof(memory_block_header_t) >
        (uintptr_t)heap_end) {
        return 0;
    }

    memory_block_header_t* h = (memory_block_header_t*)ptr;

    size_t this_size = h->size_and_flags & ~(size_t)FLAGS_MASK;
    if (this_size < sizeof(memory_block_header_t)) {
        return 0;
    }
    if ((uintptr_t)ptr + this_size > (uintptr_t)heap_end) {
        return 0;
    }
    if (this_size % ALIGNMENT_SIZE != 0) {
        return 0;
    }

    return 1;
}

/*
 * Compute the number of usable payload bytes for a block,
 * excluding the header and trailing canary.
 */
static size_t payload_usable_size(memory_block_header_t* block) {
    if (block == NULL) {
        return 0;
    }

    size_t block_total = GET_ACTUAL_SIZE(block);
    if (block_total <=
        sizeof(memory_block_header_t) + PAYLOAD_CANARY_SIZE) {
        return 0;
    }

    return block_total
        - sizeof(memory_block_header_t)
        - PAYLOAD_CANARY_SIZE;
}

/*
 * Write a fixed 64-bit canary value immediately after the usable payload.
 * This is used to detect buffer overflows into metadata.
 */
static void set_payload_canary(memory_block_header_t* block) {
    if (block == NULL) {
        return;
    }

    uint8_t* payload = get_payload_from_header(block);
    size_t usable = payload_usable_size(block);
    if (usable == 0) {
        return;
    }

    uint8_t* canary_pos = payload + usable;
    uint64_t* cptr = (uint64_t*)canary_pos;
    *cptr = (uint64_t)PAYLOAD_CANARY_VALUE;
}

/*
 * Check whether the canary word after the payload still matches the
 * expected constant value.
 *
 * Returns:
 *   0 if the canary is intact,
 *   1 if the canary has changed or the block is invalid.
 */
static int validate_payload_canary(memory_block_header_t* block) {
    if (block == NULL) {
        return 1;
    }

    uint8_t* payload = get_payload_from_header(block);
    size_t usable = payload_usable_size(block);
    if (usable == 0) {
        return 1;
    }

    uint8_t* canary_pos = payload + usable;
    uint64_t stored = *(uint64_t*)canary_pos;

    if (stored != (uint64_t)PAYLOAD_CANARY_VALUE) {
        return 1;
    }

    return 0;
}

/*
 * Safely follow the next_free_block pointer from a given free block.
 * Validates that the pointer lies inside the heap and that the header
 * looks consistent. Corrupted neighbours are quarantined.
 */
static memory_block_header_t* safe_next_free(
    heap_system_control_block_t* control,
    memory_block_header_t* b)
{
    if (!b || !control) {
        return NULL;
    }

    memory_block_header_t* n = b->next_free_block;
    if (!n) {
        return NULL;
    }

    if (!is_pointer_in_heap_and_aligned(n, control)) {
        b->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(b);
        return NULL;
    }

    if (validate_block_integrity(n) != 0) {
        n->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(n);
        return NULL;
    }

    return n;
}

/*
 * Perform local sanity checks on a block header:
 *  - mirrored fields must match
 *  - size must be non-zero, aligned, and large enough for a header
 *  - the whole block must lie inside the managed heap
 *
 * Returns 0 if the header looks consistent, 1 otherwise.
 */
static int validate_block_integrity(memory_block_header_t* b) {
    if (b == NULL || heap_base_address == NULL || heap_capacity == 0) {
        return 1;
    }

    /* Check mirrored fields for consistency. */
    if (b->size_and_flags != b->size_and_flags_mirror) {
        return 1;
    }
    if (b->prev_phys_size != b->prev_phys_size_mirror) {
        return 1;
    }

    size_t sz = b->size_and_flags & ~(size_t)FLAGS_MASK;
    if (sz == 0 || (sz % ALIGNMENT_SIZE) != 0) {
        return 1;
    }
    if (sz < sizeof(memory_block_header_t)) {
        return 1;
    }

    /* Block must lie entirely inside the heap. */
    uint8_t* heap_start =
        heap_base_address + sizeof(heap_system_control_block_t);
    uint8_t* heap_end = heap_base_address + heap_capacity;

    uint8_t* block_start = (uint8_t*)b;
    uint8_t* block_end = block_start + sz;

    if (block_start < heap_start || block_end > heap_end) {
        return 1;
    }

    return 0;
}

/*
 * Update the mirrored header fields for a block.
 */
static void update_block_checksum(memory_block_header_t* block) {
    if (!block) {
        return;
    }

    block->size_and_flags_mirror = block->size_and_flags;
    block->prev_phys_size_mirror = block->prev_phys_size;
}

/*
 * Update the prev_phys_size field of the block that comes immediately
 * after 'current' in memory, if that block looks valid.
 */
static void update_next_prev_size(
    heap_system_control_block_t* control,
    memory_block_header_t* current)
{
    if (!control || !current) {
        return;
    }

    uint8_t* heap_end = heap_base_address + heap_capacity;

    uint8_t* next_addr =
        (uint8_t*)current + GET_ACTUAL_SIZE(current);

    if (next_addr >= heap_end) {
        return;
    }

    memory_block_header_t* next = (memory_block_header_t*)next_addr;

    if (validate_block_integrity(next) == 0) {
        next->prev_phys_size = GET_ACTUAL_SIZE(current);
        next->prev_phys_size_mirror = next->prev_phys_size;
        update_block_checksum(next);
    }
    else {
        next->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(next);
    }
}

/*
 * Fill the payload area of a block with the UNUSED signature pattern.
 */
static void fill_payload_unused_signature(memory_block_header_t* block) {
    if (block == NULL) {
        return;
    }

    uint8_t* payload = get_payload_from_header(block);
    size_t usable = payload_usable_size(block);
    if (usable == 0) {
        return;
    }

    for (size_t i = 0; i < usable; i++) {
        payload[i] = UNUSED_SIGNATURE[i % SIGNATURE_LENGTH];
    }
}

/*
 * Insert a block at the head of the explicit free list, unless it is
 * already quarantined or the current head looks invalid.
 */
static void insert_into_free_list(
    heap_system_control_block_t* control,
    memory_block_header_t* block)
{
    if (!control || !block) {
        return;
    }

    if (block->size_and_flags & BLOCK_IS_QUARANTINED) {
        return;
    }

    block->prev_free_block = NULL;
    block->next_free_block = control->master_free_list;

    if (control->master_free_list != NULL) {
        if (is_pointer_in_heap_and_aligned(
            control->master_free_list, control)) {
            control->master_free_list->prev_free_block = block;
        }
        else {
            control->master_free_list->size_and_flags |=
                BLOCK_IS_QUARANTINED;
            update_block_checksum(control->master_free_list);
            control->master_free_list = NULL;
            block->next_free_block = NULL;
        }
    }

    control->master_free_list = block;
    update_block_checksum(block);
}

/*
 * Remove a block from the explicit free list, carefully checking that
 * neighbour pointers are still inside the heap.
 */
static void remove_from_free_list(
    heap_system_control_block_t* control,
    memory_block_header_t* block)
{
    if (control == NULL || block == NULL) {
        return;
    }

    if (block->prev_free_block != NULL) {
        if (is_pointer_in_heap_and_aligned(
            block->prev_free_block, control)) {
            block->prev_free_block->next_free_block =
                block->next_free_block;
        }
        else {
            block->prev_free_block->size_and_flags |=
                BLOCK_IS_QUARANTINED;
            update_block_checksum(block->prev_free_block);
        }
    }
    else {
        if (control->master_free_list == block) {
            control->master_free_list = block->next_free_block;

            if (control->master_free_list != NULL &&
                !is_pointer_in_heap_and_aligned(
                    control->master_free_list, control)) {
                control->master_free_list = NULL;
            }
        }
    }

    if (block->next_free_block != NULL) {
        if (is_pointer_in_heap_and_aligned(
            block->next_free_block, control)) {
            block->next_free_block->prev_free_block =
                block->prev_free_block;
        }
        else {
            block->next_free_block->size_and_flags |=
                BLOCK_IS_QUARANTINED;
            update_block_checksum(block->next_free_block);
        }
    }

    block->prev_free_block = NULL;
    block->next_free_block = NULL;
}

/*
 * Use a specific free block to satisfy an allocation request.
 * If there is enough leftover space, the block is split into
 * a used block plus a new smaller free block.
 */
static void* allocate_from_block(
    heap_system_control_block_t* control,
    memory_block_header_t* blk,
    size_t total_required_size,
    size_t user_size)
{
    (void)user_size;

    if (control == NULL || blk == NULL) {
        return NULL;
    }

    uintptr_t payload_candidate =
        (uintptr_t)blk + sizeof(memory_block_header_t);
    if (payload_candidate % ALIGNMENT_SIZE != 0) {
        return NULL;
    }

    size_t available_size = GET_ACTUAL_SIZE(blk);
    if (available_size < total_required_size) {
        return NULL;
    }

    size_t remaining_space = available_size - total_required_size;

    if (remaining_space >= MIN_SPLIT_THRESHOLD) {
        uint8_t* new_block_address =
            (uint8_t*)blk + total_required_size;
        memory_block_header_t* new_free_block =
            (memory_block_header_t*)new_block_address;

        new_free_block->size_and_flags =
            (remaining_space & ~(FLAGS_MASK));
        new_free_block->prev_phys_size = total_required_size;
        new_free_block->next_free_block = NULL;
        new_free_block->prev_free_block = NULL;

        remove_from_free_list(control, blk);

        blk->size_and_flags = total_required_size | BLOCK_IS_USED;

        set_payload_canary(blk);
        update_block_checksum(blk);

        insert_into_free_list(control, new_free_block);
        update_block_checksum(new_free_block);
        update_next_prev_size(control, new_free_block);
    }
    else {
        remove_from_free_list(control, blk);
        blk->size_and_flags |= BLOCK_IS_USED;

        set_payload_canary(blk);
        update_block_checksum(blk);

        uint8_t* heap_end = heap_base_address + heap_capacity;
        uint8_t* next_block_addr =
            (uint8_t*)blk + available_size;

        if (next_block_addr < heap_end) {
            memory_block_header_t* next_block =
                (memory_block_header_t*)next_block_addr;
            if (validate_block_integrity(next_block) == 0) {
                update_block_checksum(next_block);
            }
            else {
                next_block->size_and_flags |= BLOCK_IS_QUARANTINED;
                update_block_checksum(next_block);
            }
        }
    }

    uint8_t* payload_ptr =
        (uint8_t*)blk + sizeof(memory_block_header_t);
    return (void*)payload_ptr;
}

/*
 * Given a payload pointer, return its associated block header
 * if it lies inside the managed heap. Otherwise return NULL.
 */
memory_block_header_t* get_header_from_payload(void* ptr) {
    if (ptr == NULL || heap_base_address == NULL || heap_capacity == 0) {
        return NULL;
    }

    uint8_t* heap_start =
        heap_base_address + sizeof(heap_system_control_block_t);
    uint8_t* heap_end = heap_base_address + heap_capacity;

    memory_block_header_t* header =
        (memory_block_header_t*)(
            (uint8_t*)ptr - sizeof(memory_block_header_t));

    if ((uint8_t*)header < heap_start) {
        return NULL;
    }
    if ((uint8_t*)header + sizeof(memory_block_header_t) > heap_end) {
        return NULL;
    }

    return header;
}

/*
 * Initialise the allocator to manage a caller-provided heap region.
 */
int mm_init(uint8_t* heap, size_t heap_size) {
    const size_t MIN_REQUIRED_MEMORY =
        sizeof(heap_system_control_block_t)
        + sizeof(memory_block_header_t)
        + ALIGNMENT_SIZE;

    if (heap == NULL || heap_size < MIN_REQUIRED_MEMORY) {
        return -1;
    }

    heap_base_address = heap;
    heap_capacity = heap_size;

    heap_system_control_block_t* system_ctrl =
        GET_SYSTEM_CONTROL(heap_base_address);

    system_ctrl->system_start_ptr = heap_base_address;
    system_ctrl->total_memory_capacity = heap_size;
    system_ctrl->master_free_list = NULL;

    uint8_t* area_start =
        heap_base_address + sizeof(heap_system_control_block_t);
    uint8_t* area_end = heap_base_address + heap_size;

    uintptr_t payload_candidate =
        (uintptr_t)(area_start + sizeof(memory_block_header_t));
    uintptr_t payload_aligned;

    if (payload_candidate % ALIGNMENT_SIZE == 0) {
        payload_aligned = payload_candidate;
    }
    else {
        payload_aligned =
            ((payload_candidate / ALIGNMENT_SIZE) + 1)
            * ALIGNMENT_SIZE;
    }

    uint8_t* payload_start = (uint8_t*)payload_aligned;

    memory_block_header_t* initial_free_block =
        (memory_block_header_t*)(
            payload_start - sizeof(memory_block_header_t));

    if ((uint8_t*)initial_free_block < area_start ||
        (uint8_t*)initial_free_block >= area_end) {
        return -1;
    }

    size_t initial_block_size =
        (size_t)(area_end - (uint8_t*)initial_free_block);
    size_t rem = initial_block_size % ALIGNMENT_SIZE;

    if (rem != 0) {
        initial_block_size -= rem;
    }
    if (initial_block_size < sizeof(memory_block_header_t)) {
        return -1;
    }

    initial_free_block->size_and_flags =
        initial_block_size & ~(FLAGS_MASK);
    initial_free_block->prev_phys_size = 0;
    initial_free_block->next_free_block = NULL;
    initial_free_block->prev_free_block = NULL;

    system_ctrl->master_free_list = initial_free_block;
    update_block_checksum(initial_free_block);

    /* Mark the initial payload area as unused using the signature. */
    uint8_t* payload_area_start =
        (uint8_t*)initial_free_block + sizeof(memory_block_header_t);
    size_t total_payload_area =
        initial_block_size - sizeof(memory_block_header_t);

    for (size_t i = 0; i < total_payload_area; i++) {
        payload_area_start[i] = UNUSED_SIGNATURE[i % SIGNATURE_LENGTH];
    }

    return 0;
}

/*
 * Allocate a block with at least 'size' bytes of usable payload.
 * Uses a first-fit walk over the explicit free list.
 */
void* mm_malloc(size_t size) {
    if (heap_base_address == NULL) {
        return NULL;
    }

    heap_system_control_block_t* control =
        GET_SYSTEM_CONTROL(heap_base_address);

    if (size == 0) {
        return NULL;
    }

    size_t required_payload_and_header =
        size + sizeof(memory_block_header_t) + PAYLOAD_CANARY_SIZE;
    size_t total_required_size = required_payload_and_header;

    if (total_required_size % ALIGNMENT_SIZE != 0) {
        total_required_size +=
            ALIGNMENT_SIZE - (total_required_size % ALIGNMENT_SIZE);
    }

    memory_block_header_t* current = control->master_free_list;

    while (current != NULL) {
        if (!is_pointer_in_heap_and_aligned(current, control)) {
            /* Free list head looks invalid: drop the list for safety. */
            control->master_free_list = NULL;
            break;
        }

        memory_block_header_t* next = safe_next_free(control, current);

        if (validate_block_integrity(current) != 0) {
            current->size_and_flags |= BLOCK_IS_QUARANTINED;
            update_block_checksum(current);
            remove_from_free_list(control, current);
            current = next;
            continue;
        }

        size_t available_size = GET_ACTUAL_SIZE(current);
        if (available_size >= total_required_size) {
            void* res = allocate_from_block(
                control, current, total_required_size, size);
            if (res != NULL) {
                return res;
            }
        }

        current = next;
    }

    return NULL;
}

/*
 * Free a payload pointer previously returned by mm_malloc.
 * Attempts to coalesce with adjacent free blocks and fills
 * the payload with the UNUSED signature.
 */
void mm_free(void* ptr) {
    if (ptr == NULL) {
        return;
    }

    if (heap_base_address == NULL) {
        return;
    }

    heap_system_control_block_t* control =
        GET_SYSTEM_CONTROL(heap_base_address);
    memory_block_header_t* block = get_header_from_payload(ptr);

    if (block == NULL) {
        return;
    }

    if (validate_block_integrity(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return;
    }

    if (validate_payload_canary(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return;
    }

    /* Already free: treat as suspicious and quarantine. */
    if (!(block->size_and_flags & BLOCK_IS_USED)) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        fill_payload_unused_signature(block);
        remove_from_free_list(control, block);
        update_block_checksum(block);
        return;
    }

    block->size_and_flags &= ~BLOCK_IS_USED;
    fill_payload_unused_signature(block);

    memory_block_header_t* current = block;

    /*
     * Backward coalescing: try to merge with the previous physical block
     * if its size looks sane and it is a free, valid block.
     */
    if (current->prev_phys_size != 0) {
        size_t prev_size = current->prev_phys_size;

        uint8_t* heap_start =
            heap_base_address + sizeof(heap_system_control_block_t);
        uint8_t* heap_end = heap_base_address + heap_capacity;

        int prev_size_ok =
            (prev_size % ALIGNMENT_SIZE == 0) &&
            (prev_size >=
                sizeof(memory_block_header_t) + ALIGNMENT_SIZE) &&
            (prev_size <=
                (size_t)((uint8_t*)current - heap_start));

        if (prev_size_ok) {
            uint8_t* prev_addr = (uint8_t*)current - prev_size;

            if (prev_addr >= heap_start &&
                prev_addr + sizeof(memory_block_header_t) <=
                heap_end) {
                memory_block_header_t* prev_block =
                    (memory_block_header_t*)prev_addr;

                if (validate_block_integrity(prev_block) == 0 &&
                    !(prev_block->size_and_flags & BLOCK_IS_USED)) {
                    remove_from_free_list(control, prev_block);

                    size_t new_size =
                        GET_ACTUAL_SIZE(prev_block) +
                        GET_ACTUAL_SIZE(current);

                    prev_block->size_and_flags =
                        new_size & ~(FLAGS_MASK);
                    update_block_checksum(prev_block);

                    current = prev_block;
                }
            }
        }
    }

    /* Forward coalescing: try to merge with the next physical block. */
    uint8_t* heap_end = heap_base_address + heap_capacity;
    uint8_t* next_addr =
        (uint8_t*)current + GET_ACTUAL_SIZE(current);

    if (next_addr < heap_end) {
        memory_block_header_t* next_block =
            (memory_block_header_t*)next_addr;

        if (validate_block_integrity(next_block) == 0 &&
            !(next_block->size_and_flags & BLOCK_IS_USED)) {
            remove_from_free_list(control, next_block);

            size_t new_size =
                GET_ACTUAL_SIZE(current) +
                GET_ACTUAL_SIZE(next_block);

            current->size_and_flags = new_size & ~(FLAGS_MASK);
        }
    }

    insert_into_free_list(control, current);
    update_next_prev_size(control, current);
    update_block_checksum(current);
}

/*
 * Bounded and integrity-checked read from an allocated block.
 */
int mm_read(void* ptr, size_t offset, void* buf, size_t len) {
    if (ptr == NULL || buf == NULL || len == 0) {
        return -1;
    }

    if (heap_base_address == NULL) {
        return -1;
    }

    heap_system_control_block_t* control =
        GET_SYSTEM_CONTROL(heap_base_address);
    if (control == NULL) {
        return -1;
    }

    memory_block_header_t* block = get_header_from_payload(ptr);
    if (block == NULL) {
        return -1;
    }

    if (validate_block_integrity(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return -1;
    }

    if (!(block->size_and_flags & BLOCK_IS_USED)) {
        return -1;
    }

    size_t usable = payload_usable_size(block);
    if (offset + len > usable) {
        return -1;
    }

    if (validate_payload_canary(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return -1;
    }

    uint8_t* payload = get_payload_from_header(block);
    memcpy(buf, payload + offset, len);

    return (int)len;
}

/*
 * Bounded and integrity-checked write into an allocated block.
 */
int mm_write(void* ptr, size_t offset, const void* src, size_t len) {
    if (ptr == NULL || src == NULL || len == 0) {
        return -1;
    }

    if (heap_base_address == NULL) {
        return -1;
    }

    heap_system_control_block_t* control =
        GET_SYSTEM_CONTROL(heap_base_address);
    if (control == NULL) {
        return -1;
    }

    memory_block_header_t* block = get_header_from_payload(ptr);
    if (block == NULL) {
        return -1;
    }

    if (validate_block_integrity(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return -1;
    }

    if (!(block->size_and_flags & BLOCK_IS_USED)) {
        return -1;
    }

    size_t usable = payload_usable_size(block);
    if (offset + len > usable) {
        return -1;
    }

    if (validate_payload_canary(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return -1;
    }

    uint8_t* payload = get_payload_from_header(block);
    memcpy(payload + offset, src, len);

    set_payload_canary(block);

    return (int)len;
}

/*
 * mm_realloc:
 *   Resize an existing allocation while preserving data.
 *
 * Behaviour:
 *   - If ptr == NULL and new_size > 0, behaves like mm_malloc.
 *   - If new_size == 0, frees the block and returns NULL.
 *   - Otherwise, validates the existing block, and:
 *       * if the current payload is large enough, reuses in-place;
 *       * else allocates a new block, copies data, then frees old.
 *
 * On failure, the original allocation remains valid.
 */
void* mm_realloc(void* ptr, size_t new_size) {
    /* Case 1: behave like malloc when ptr == NULL. */
    if (ptr == NULL) {
        if (new_size == 0) {
            return NULL;
        }
        return mm_malloc(new_size);
    }

    /* Case 2: new_size == 0 is equivalent to free + NULL. */
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    /* Heap not initialised. */
    if (heap_base_address == NULL) {
        return NULL;
    }

    heap_system_control_block_t* control =
        GET_SYSTEM_CONTROL(heap_base_address);
    if (control == NULL) {
        return NULL;
    }

    /* Retrieve the block header for this payload. */
    memory_block_header_t* block = get_header_from_payload(ptr);
    if (block == NULL) {
        return NULL;
    }

    /* 1) Header integrity check. */
    if (validate_block_integrity(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return NULL;
    }

    /* 2) Detect use-after-free or invalid pointer. */
    if (!(block->size_and_flags & BLOCK_IS_USED)) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        fill_payload_unused_signature(block);
        remove_from_free_list(control, block);
        update_block_checksum(block);
        return NULL;
    }

    /* 3) Canary check to detect out-of-bounds writes. */
    if (validate_payload_canary(block) != 0) {
        block->size_and_flags |= BLOCK_IS_QUARANTINED;
        update_block_checksum(block);
        remove_from_free_list(control, block);
        return NULL;
    }

    size_t old_usable = payload_usable_size(block);

    /* If the existing block is large enough, reuse it in place. */
    if (new_size <= old_usable) {
        return ptr;
    }

    /* Otherwise, allocate a new block and copy the data. */
    void* new_ptr = mm_malloc(new_size);
    if (new_ptr == NULL) {
        /* On failure, original pointer must remain valid. */
        return NULL;
    }

    memory_block_header_t* new_block = get_header_from_payload(new_ptr);
    if (new_block == NULL) {
        /* Very unexpected: avoid leak by freeing the new block. */
        mm_free(new_ptr);
        return NULL;
    }

    size_t new_usable = payload_usable_size(new_block);
    if (new_usable == 0) {
        mm_free(new_ptr);
        return NULL;
    }

    /* Copy min(old_usable, new_usable) bytes. */
    size_t copy_size = (old_usable < new_usable) ? old_usable : new_usable;

    uint8_t* old_payload = get_payload_from_header(block);
    uint8_t* new_payload = get_payload_from_header(new_block);

    memcpy(new_payload, old_payload, copy_size);

    /* Re-write canary and header mirrors for the new block. */
    set_payload_canary(new_block);
    update_block_checksum(new_block);

    /* Free the old block; mm_free will handle coalescing. */
    mm_free(ptr);

    return new_ptr;
}
