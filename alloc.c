#include <memory.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <unistd.h>

typedef struct Allocator {
    void *(*alloc)(void *impl, size_t size);
    void (*free)(void *impl, void *ptr);
} Allocator;

typedef union BlockHeader {
    struct {
        size_t metadata;
        union BlockHeader *next, *prev;
    } free_block;
    struct {
        size_t metadata;
        size_t canary;
    } alloc_block;
} BlockHeader;

typedef struct HeapRegionHeader {
    size_t size;
    struct HeapRegionHeader *next;
} HeapRegionHeader;

typedef struct GeneralPurposeAllocator {
    HeapRegionHeader *(*acquire)(size_t size);
    void (*release)(HeapRegionHeader *region);

    HeapRegionHeader *first_region;
    BlockHeader *first, *next, *last;
} GeneralPurposeAllocator, Gpa;

static size_t get_block_size(BlockHeader *b) {
    return b->free_block.metadata & ~0xfUL;
}

static void set_block_size(BlockHeader *b, size_t size) {
    b->free_block.metadata = size | (b->free_block.metadata & 0xfUL);
}

static bool is_allocated(BlockHeader *b) { return b->free_block.metadata & 1; }

static void set_allocated(BlockHeader *b, bool allocated) {
    b->free_block.metadata =
        (b->free_block.metadata & ~0xfU) | (allocated != 0);
}

static HeapRegionHeader *def_gpa_acquire(size_t alloc_size) {
    return mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
}

static void def_gpa_release(HeapRegionHeader *region) {
    munmap(region, region->size);
}

void gpa_init(Gpa *gpa) {
    gpa->first_region = NULL;
    gpa->first = gpa->last = gpa->next = NULL;
    gpa->acquire = def_gpa_acquire;
    gpa->release = def_gpa_release;
}

void gpa_deinit(Gpa *gpa) {
    HeapRegionHeader *hr = gpa->first_region;

    while (hr) {
        HeapRegionHeader *next = hr->next;

        gpa->release(hr);

        hr = next;
    }
}

static void insert_block(Gpa *gpa, BlockHeader *b) {
    BlockHeader *tmp = gpa->last;

    while (tmp && get_block_size(b) < get_block_size(tmp)) {
        tmp = tmp->free_block.prev;
    }

    if (tmp) {
        BlockHeader *next = tmp->free_block.next;
        tmp->free_block.next = b;
        b->free_block.next = next;

        if (next) {
            next->free_block.prev = b;
        }
    } else {
        BlockHeader *next = gpa->first;
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

static void remove_block(Gpa *gpa, BlockHeader *b) {
    BlockHeader *prev;
    if ((prev = b->free_block.prev)) {
        BlockHeader *next = b->free_block.next;
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
        }
    }
}

BlockHeader *search_until(BlockHeader *b, BlockHeader *term,
                          size_t total_size) {
    while (b != term) {
        BlockHeader *next = b->free_block.next;

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

void *gpa_alloc(Gpa *gpa, size_t size) {
    size = (size + 15) & ~15; // align to 16 bytes.
    size_t total_size = size + sizeof(gpa->first->alloc_block);

    BlockHeader *b = gpa->next;

    b = search_until(b, NULL, total_size);

    if (!b) {
        b = search_until(gpa->first, gpa->next, total_size);
    }

    if (!b) {
        // Allocate new memory.
        const size_t region_overhead = sizeof(HeapRegionHeader);
        size_t alloc_size = align_to_page(total_size + region_overhead);
        HeapRegionHeader *hr = gpa->acquire(alloc_size);
        hr->size = alloc_size;

        hr->next = gpa->first_region;
        gpa->first_region = hr;

        b = (BlockHeader *)(hr + 1);
        set_block_size(b, alloc_size - region_overhead);

        insert_block(gpa, b);

        gpa->next = NULL;
    } else {
        gpa->next = b->free_block.next;
    }

    // split.
    size_t excess = get_block_size(b) - total_size;
    if (excess >= sizeof(b->alloc_block) + 16) {
        // split. don't need to remove the block--we shrink it.
        BlockHeader *new_block = b;
        b = (BlockHeader *)((char *)b + excess);

        set_block_size(new_block, excess);
    } else {
        // need to remove the block here. didn't split.
        remove_block(gpa, b);
    }

    if (!gpa->next) {
        gpa->next = gpa->first;
    }

    set_allocated(b, true);

    return (void *)(&b->alloc_block + 1);
}

static bool coalesce_with_next(Gpa *gpa, BlockHeader *block) {
    if (!block)
        return false;

    BlockHeader *next = block->free_block.next;

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

void gpa_free(Gpa *gpa, void *ptr) {
    BlockHeader *block =
        (BlockHeader *)((char *)ptr - sizeof(block->alloc_block));
    set_allocated(block, false);

    insert_block(gpa, block);

    BlockHeader *prev = block->free_block.prev;

    if (coalesce_with_next(gpa, prev)) {
        block = prev;
    }

    coalesce_with_next(gpa, block);
}

static void shrink_block_split_right(Gpa *gpa, BlockHeader *block, size_t new_block_size) {
    size_t block_size = get_block_size(block);
    size_t excess = block_size - new_block_size;
    if (excess >= sizeof(block->alloc_block) + 16) {
        BlockHeader *new_block = (BlockHeader *)((char *)block + excess);
        set_block_size(new_block, excess);
        insert_block(gpa, new_block);
    }
}

static void *reallocate(Gpa *gpa, void *ptr, size_t old_size, size_t new_size) {
        void *new_block = gpa_alloc(gpa, new_size);
        memcpy(new_block, ptr, old_size);
        gpa_free(gpa, ptr);

        return new_block;
}

// FIXME: SOOOOO BROKEN.....
void *gpa_realloc(Gpa *gpa, void *ptr, size_t new_size) {
    new_size = (new_size + 15) & ~15;
    BlockHeader *block =
        (BlockHeader *)((char *)ptr - sizeof(block->alloc_block));

    size_t new_block_size = new_size + sizeof(block->alloc_block);

    size_t block_size = get_block_size(block);
    size_t old_size = block_size - sizeof(block->alloc_block);

    if (new_size == old_size) {
        return ptr;
    }

    if (new_size < old_size) {
        // shrink the block.
        shrink_block_split_right(gpa, block, new_block_size);
        return ptr;
    }

    uintptr_t next_start = (uintptr_t)block + get_block_size(block);

    BlockHeader *tmp = gpa->first;

    while (tmp && (uintptr_t)tmp != next_start) {
        tmp = tmp->free_block.next;
    }

    if (tmp) {
        size_t additional = get_block_size(tmp);
        size_t total = block_size + additional;

        if (total < new_size) {
            goto def;
        } else {
            // use part of the new_block.
            remove_block(gpa, tmp);
            size_t tmp_new_block_size = new_block_size - block_size;
            shrink_block_split_right(gpa, tmp, tmp_new_block_size);

            set_block_size(block, new_size);
        }
    }

def:
    return reallocate(gpa, ptr, block_size - sizeof(block->alloc_block), new_size);
}

void print_heap(Gpa *gpa) {
    printf("Heap Dump:\n");
    printf("Regions:\n");

    HeapRegionHeader *region = gpa->first_region;
    while (region) {
        printf("  Region at %p, size: %zu\n", (void *)region, region->size);
        region = region->next;
    }

    printf("\nBlocks:\n");
    BlockHeader *block = gpa->first;
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
    Gpa g;
    gpa_init(&g);

    int(*pints)[4][4] = gpa_alloc(&g, sizeof(int[4][4]));

    int *stuff = gpa_alloc(&g, sizeof(int));

    char *huge_buf = gpa_alloc(&g, 1024);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            (*pints)[r][c] = r + c;
        }
    }

    print_heap(&g);

    int nread = read(STDIN_FILENO, huge_buf, 511);
    huge_buf[nread] = 0;

    printf("We read in: %s\n", huge_buf);

    print_heap(&g);

    gpa_free(&g, pints);

    gpa_free(&g, stuff);

    gpa_free(&g, huge_buf);

    gpa_deinit(&g);
}
