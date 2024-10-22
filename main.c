#define SOL_DEF
#include "sol.h"
#include "names.h"

struct thing {
    u64 i;
    char *s;
    char c;
};

def_typed_array(thing, struct thing)

int main() {
    
    allocator_t alloc;
    create_allocator_arena(4096, &alloc);
    
    string_array_t arr;
    create_string_array(16, 16, &alloc, &arr);
    
    for(int i=0; i < cl_array_size(names); ++i) {
        struct string s;
        s.data = names[i];
        s.size = strlen(names[i]);
        assert(string_array_add(&arr, s) == 0);
    }
    
    char buf[128];
    struct string s;
    for(int i=0; i < cl_array_size(names); ++i) {
        s.data = NULL;
        log_error_if(string_array_get(&arr, i, &s), "Error getting size on %u", i);
        
        s.data = buf;
        log_error_if(string_array_get(&arr, i, &s), "Error getting string on %u", i);
        println("buf %s", s.data);
        assert(memcmp(s.data, names[i], s.size + 1) == 0);
        
        s = string_array_get_raw(&arr, i);
        println("raw %s", s.data);
        assert(memcmp(s.data, names[i], s.size + 1) == 0);
    }
    
    s.size = 3;
    if (string_array_get(&arr, 0, &s)) {
        println("TRUNCATE - full %s, got %s", names[0], s.data);
    }
    
    return 0;
}