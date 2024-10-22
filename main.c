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
    
    thing_dict_t dict;
    create_thing_dict(16, &alloc, &dict);
    
    for(u32 i=0; i < cl_array_size(names); ++i) {
        struct thing t;
        t.i = i;
        t.s = names[i];
        t.c = names[i][0];
        
        assert(thing_dict_insert(&dict, STR(names[i]), &t) == 0);
    }
    
    
    for(u32 i=0; i < cl_array_size(names); ++i) {
        struct thing t;
        assert(thing_dict_find(&dict, STR(names[i]), &t));
        assert(t.i == i && strcmp(t.s, names[i]) == 0 && names[i][0] == t.c);
        
        println("%u: %s | %s", i, t.s, names[i]);
    }
    
    thing_dict_iter_t it;
    thing_dict_get_iter(&dict, &it);
    
    struct thing t;
    dict_for_each(&t, &it, thing_dict_iter_next) {
        println("%u: %s | %s", t.i, t.s, names[t.i]);
    }
    
#if 0
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
#endif
    
    return 0;
}