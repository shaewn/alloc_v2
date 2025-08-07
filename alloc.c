#include <memory.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <unistd.h>

typedef union {
    struct {
        size_t metadata;
        union BlockHeader *next, *prev;
    } free_block;
    struct {
        size_t metadata;
        size_t canary;
    } alloc_block;
} block_header_t;

typedef struct heap_region_header {
    size_t size;
    struct heap_region_header *next;
} heap_region_header_t;

typedef struct gpa {
    void *user;
    heap_region_header_t *(*acquire)(void *user, size_t size);
    void (*release)(void *user, heap_region_header_t *region);

    heap_region_header_t *first_region;
    block_header_t *first, *next, *last;
} gpa_t;

#define GPA_INITIALIZER(user, acq, rel) { user, acq, rel, NULL, NULL, NULL, NULL }
#define GPA_DEF_INIT { NULL, def_gpa_acquire, def_gpa_release, NULL, NULL, NULL, NULL }

static size_t get_block_size(block_header_t *b) {
    return b->free_block.metadata & ~0xfUL;
}

static void set_block_size(block_header_t *b, size_t size) {
    b->free_block.metadata = size | (b->free_block.metadata & 0xf);
}

static bool is_allocated(block_header_t *b) { return b->free_block.metadata & 1; }

static void set_allocated(block_header_t *b, bool allocated) {
    b->free_block.metadata =
        (b->free_block.metadata & ~0xfULL) | (allocated != 0);
}

static heap_region_header_t *def_gpa_acquire(void *user, size_t alloc_size) {
    return mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
}

static void def_gpa_release(void *user, heap_region_header_t *region) {
    munmap(region, region->size);
}

void gpa_init(gpa_t *gpa, void *user, heap_region_header_t *(*acquire)(void *user, size_t size), void (*release)(void *user, heap_region_header_t *region)) {
    gpa->first_region = NULL;
    gpa->first = gpa->last = gpa->next = NULL;
    gpa->user = user;
    gpa->acquire = acquire;
    gpa->release = release;
}

void gpa_deinit(gpa_t *gpa) {
    heap_region_header_t *hr = gpa->first_region;

    while (hr) {
        heap_region_header_t *next = hr->next;

        gpa->release(gpa->user, hr);

        hr = next;
    }
}

static void insert_block(gpa_t *gpa, block_header_t *b) {
    block_header_t *tmp = gpa->last;

    while (tmp && (uintptr_t)b < (uintptr_t)tmp) {
        tmp = tmp->free_block.prev;
    }

    if (tmp) {
        block_header_t *next = tmp->free_block.next;
        tmp->free_block.next = b;
        b->free_block.next = next;

        if (next) {
            next->free_block.prev = b;
        }
    } else {
        block_header_t *next = gpa->first;
        gpa->first = b;
        b->free_block.next = next;

        if (next) {
            next->free_block.prev = b;
        }
    }

    b->free_block.prev = tmp;

    if (!b->free_block.next) {
        gpa->last = b;
    }
}

static void remove_block(gpa_t *gpa, block_header_t *b) {
    block_header_t *prev;
    if ((prev = b->free_block.prev)) {
        block_header_t *next = b->free_block.next;
        prev->free_block.next = next;
        if (!next) {
            gpa->last = prev;
        } else {
            next->free_block.prev = prev;
        }
    } else {
        gpa->first = b->free_block.next;
        if (!gpa->first) {
            gpa->last = NULL;
        } else {
            gpa->first->free_block.prev = NULL;
        }
    }
}

block_header_t *search_until(block_header_t *b, block_header_t *term,
                          size_t total_size) {
    while (b != term) {
        block_header_t *next = b->free_block.next;

        if (get_block_size(b) >= total_size) {
            return b;
        } else {
            b = next;
        }
    }

    return NULL;
}

size_t align_to_page(size_t size) {
    unsigned page = sysconf(_SC_PAGESIZE);
    unsigned page_minus_one = page - 1;
    return (size + page_minus_one) & ~page_minus_one;
}

static bool coalesce_with_next(gpa_t *gpa, block_header_t *block) {
    if (!block)
        return false;

    block_header_t *next = block->free_block.next;

    if (!next)
        return false;

    if ((uintptr_t)next != (uintptr_t)block + get_block_size(block))
        return false; // Not contiguous.

    remove_block(gpa, next);

    if (gpa->next == next) {
        gpa->next = block;
    }

    set_block_size(block, get_block_size(block) + get_block_size(next));
    return true;
}

static void shrink_block_split_right(gpa_t *gpa, block_header_t *block, size_t new_block_size) {
    size_t block_size = get_block_size(block);
    size_t excess = block_size - new_block_size;
    if (excess >= sizeof(block->alloc_block) + 16) {
        block_header_t *new_block = (block_header_t *)((char *)block + new_block_size);
        set_block_size(new_block, excess);
        set_block_size(block, new_block_size);
        insert_block(gpa, new_block);
        // There is no need to coalesce here, since 'block' is free, and would've already been coalesced.
        // i.e., there's no more free stuff on that end.
    }
}

void *gpa_alloc(gpa_t *gpa, size_t size) {
    if (size == 0) return NULL;
    size = (size + 15) & ~15; // align to 16 bytes.
    size_t total_size = size + sizeof(gpa->first->alloc_block);

    block_header_t *b = gpa->next;

    b = search_until(b, NULL, total_size);

    if (!b) {
        b = search_until(gpa->first, gpa->next, total_size);
    }

    if (!b) {
        // Allocate new memory.
        const size_t region_overhead = sizeof(heap_region_header_t);
        size_t alloc_size = align_to_page(total_size + region_overhead);
        heap_region_header_t *hr = gpa->acquire(gpa->user, alloc_size);
        hr->size = alloc_size;

        hr->next = gpa->first_region;
        gpa->first_region = hr;

        b = (block_header_t *)(hr + 1);
        set_block_size(b, alloc_size - region_overhead);

        insert_block(gpa, b);

        gpa->next = NULL;
    } else {
        gpa->next = b->free_block.next;
    }

    // split.
    shrink_block_split_right(gpa, b, total_size);

    remove_block(gpa, b);

    if (!gpa->next) {
        gpa->next = gpa->first;
    }

    set_allocated(b, true);

    return (void *)(&b->alloc_block + 1);
}

void gpa_free(gpa_t *gpa, void *ptr) {
    block_header_t *block =
        (block_header_t *)((char *)ptr - sizeof(block->alloc_block));
    set_allocated(block, false);

    insert_block(gpa, block);

    block_header_t *prev = block->free_block.prev;

    if (coalesce_with_next(gpa, prev)) {
        block = prev;
    }

    coalesce_with_next(gpa, block);
}

static void *reallocate(gpa_t *gpa, void *ptr, size_t old_size, size_t new_size) {
        void *new_block = gpa_alloc(gpa, new_size);
        memcpy(new_block, ptr, old_size);
        gpa_free(gpa, ptr);

        return new_block;
}

void *gpa_realloc(gpa_t *gpa, void *ptr, size_t new_data_size) {
    new_data_size = (new_data_size + 15) & ~15;
    block_header_t *block =
        (block_header_t *)((char *)ptr - sizeof(block->alloc_block));

    size_t new_block_size = new_data_size + sizeof(block->alloc_block);

    size_t block_size = get_block_size(block);
    size_t old_data_size = block_size - sizeof(block->alloc_block);

    if (new_data_size == old_data_size) {
        return ptr;
    }

    if (new_data_size < old_data_size) {
        // shrink the block.
        shrink_block_split_right(gpa, block, new_block_size);
        return ptr;
    }

    uintptr_t next_start = (uintptr_t)block + get_block_size(block);

    block_header_t *tmp = block->free_block.next;

    if ((uintptr_t)tmp == next_start) {
        size_t additional = get_block_size(tmp);
        size_t total = block_size + additional;

        if (total >= new_block_size) {
            // use part of the new_block.
            remove_block(gpa, tmp);
            // the size that will be taken up by the portion we will consume.
            size_t tmp_new_block_size = new_block_size - block_size;
            shrink_block_split_right(gpa, tmp, tmp_new_block_size);

            set_block_size(block, new_block_size);

            return ptr;
        }
    }

    return reallocate(gpa, ptr, block_size - sizeof(block->alloc_block), new_data_size);
}

void print_heap(gpa_t *gpa) {
    printf("Heap Dump:\n");
    printf("Regions:\n");

    heap_region_header_t *region = gpa->first_region;
    while (region) {
        printf("  Region at %p, size: %zu\n", (void *)region, region->size);
        region = region->next;
    }

    printf("\nBlocks:\n");
    block_header_t *block = gpa->first;
    while (block) {
        printf("  Block at %p, size: %zu, %s\n", (void *)block,
               get_block_size(block),
               is_allocated(block) ? "ALLOCATED" : "FREE");
        block = block->free_block.next;
    }

    printf("\nNext allocation start: %p\n", (void *)gpa->next);
    printf("End of Heap Dump\n\n");
}

int main() {
    gpa_t g = GPA_DEF_INIT;

    const int num_ints = 10;

    int *ints = gpa_alloc(&g, sizeof(int) * num_ints);

    for (int i = 0; i < num_ints; i++) {
        ints[i] = i + 1;
    }

    print_heap(&g);

    ints = gpa_realloc(&g, ints, sizeof(int) * num_ints * 2);

    for (int i = num_ints; i < num_ints * 2; i++) {
        ints[i] = 2 * i;
    }

    print_heap(&g);

    gpa_free(&g, ints);

    print_heap(&g);

    gpa_deinit(&g);
}
