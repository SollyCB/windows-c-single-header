#define SOL_DEF
#include "sol.h"
#include "names.h"

struct thing {
    u64 i;
    char *s;
    char c;
};

def_typed_array(thing, struct thing)
def_typed_dict(thing, struct thing)

int main() {
    
    allocator_t alloc;
    create_allocator_arena(4096, &alloc);
    
    large_set_t set;
    create_large_set(1000, NULL, &alloc, &set);
    
    u32 yes = 999;
    u32 no = 514;
    
    large_set_add(set, yes);
    if (large_set_test(set, yes))
        println("%u (%s) is set", yes, "yes");
    
    if (!large_set_test(set, no))
        println("%u (%s) is not set", no, "no");
    
    large_set_rm(set, yes);
    if (!large_set_test(set, yes)) {
        println("%u (%s) is not set", yes, "yes");
    } else {
        println("%u (%s) is set", yes, "yes");
    }
    
    return 0;
}