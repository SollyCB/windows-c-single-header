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
    create_thing_dict(4, &alloc, &dict);
    
    int count = cl_array_len(names);
    
    println("\nINSERT");
    
    for(int i=0; i < count; ++i) {
        struct string key = {.data = names[i], .size = strlen(names[i])};
        struct thing thing = {.i = i, .s = names[i], .c = names[i][0]};
        if (!thing_dict_insert(&dict, key, &thing)) {
            println("FAILURE on %u", i);
            return -1;
        }
    }
    println("    Insert all good");
    
    println("\nFIND");
    
    for(int i=0; i < count; ++i) {
        struct string key = {.data = names[i], .size = strlen(names[i])};
        struct thing_dict_kv *kv = thing_dict_find(&dict, key);
        if (strcmp(kv->val.s, names[i])) {
            println("FAILURE on %u", i);
            return -1;
        }
    }
    println("    Find all good");
    
    thing_dict_iter_t iter;
    thing_dict_get_iter(&dict, &iter);
    
    println("\nITER");
    
    struct thing_dict_kv *it;
    u32 counter = 0;
    dict_for_each(it, &iter, thing_dict_iter_next) {
        bool found = false;
        for(int i=0; i < cl_array_len(names); ++i) {
            if (strcmp(names[i], it->val.s)) {
                counter++;
                found = true;
                break;
            }
        }
        if (!found) {
            println("FAILURE on %u", counter);
            return -1;
        }
    }
    println("    Iter all good");
    
    destroy_thing_dict(&dict);
    
    return 0;
}