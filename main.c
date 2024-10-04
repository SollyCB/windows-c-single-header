#define SOL_DEF
#include "sol.h"

struct thing {
    int x;
    struct list l;
};

int main() {
    
    println("page size: %u", os_page_size());
    
    u32 size = 8000;
    allocator_t alloc;
    
    create_allocator_arena(NULL, size, &alloc);
    
    void *a[4];
    void *b[4];
    void *c[4];
    void *d[4];
    
    for(int i=0; i < cl_array_len(a); ++i) {
        a[i] = allocate(&alloc, size/4);
        memset(a[i], 0xa, size/4);
        b[i] = allocate(&alloc, size/4);
        memset(b[i], 0xb, size/4);
        c[i] = allocate(&alloc, size/4);
        memset(c[i], 0xc, size/4);
        d[i] = allocate(&alloc, size/4);
        memset(d[i], 0xd, size/4);
    }
    
    println("block count: %u", alloc.arena.block_count);
    println("total size: %u", allocator_size(&alloc));
    println("total used: %u", allocator_used(&alloc));
    
    void *aa = malloc(size/4);
    memset(aa, 0xa, size/4);
    void *bb = malloc(size/4);
    memset(bb, 0xb, size/4);
    void *cc = malloc(size/4);
    memset(cc, 0xc, size/4);
    void *dd = malloc(size/4);
    memset(dd, 0xd, size/4);
    
    for(int i=0; i < cl_array_len(a); ++i) {
        assert(memcmp(a[i], aa, size/4) == 0);
        assert(memcmp(b[i], bb, size/4) == 0);
        assert(memcmp(c[i], cc, size/4) == 0);
        assert(memcmp(d[i], dd, size/4) == 0);
    }
    
    deallocate(&alloc, d[2], size/4);
    d[2] = allocate(&alloc, size/8);
    d[2] = reallocate(&alloc, d[2], size/8, size/4);
    
    return 0;
}