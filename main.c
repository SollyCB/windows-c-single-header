#if 0

#else

#define SOL_DEF
#include "sol.h"
#include "names.h"

struct thing {
    u64 i;
    char *s;
    char c;
};

def_typed_dict(thing, struct thing)

int main() {
    
    allocator_t alloc;
    create_allocator_arena(NULL, 4096, &alloc);
    
    thing_dict_t dict;
    create_thing_dict(16, &alloc, &dict);
    
    for(int i=0; i < cl_array_len(names); ++i) {
        struct thing t;
        t.i = i;
        t.s = names[i];
        t.c = names[i][0];
        assert(0 == thing_dict_insert(&dict, (struct string) {.data = names[i], .size = strlen(names[i])}, &t));
    }
    
    for(int i=0; i < cl_array_len(names); ++i) {
        struct thing r;
        assert(thing_dict_find(&dict, (struct string) {.data = names[i], .size = strlen(names[i])}, &r));
        struct thing t;
        t.i = i;
        t.s = names[i];
        t.c = names[i][0];
        println("%u, %u,  %s", i, r.i, r.s);
        log_error_if(memcmp(&t, &r, sizeof(t)), "Failed find on %u", i);
    }
    println("\n\n");
    struct thing r;
    thing_dict_iter_t it;
    thing_dict_get_iter(&dict, &it);
    dict_for_each(&r, &it, thing_dict_iter_next) {
        bool ok = 0;
        for(int i=0; i < cl_array_len(names); ++i) {
            struct thing t;
            t.i = i;
            t.s = names[i];
            t.c = names[i][0];
            if (0 == memcmp(&t, &r, sizeof(t)))
                ok = 1;
        }
        println("%u,  %s", r.i, r.s);
        log_error_if(!ok, "ITER");
    }
    
    return 0;
}
#endif