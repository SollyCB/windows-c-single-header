#if 0
#define paste(...) __VA_ARGS__

#define def_wrapper_fn(wrapper_name, wrapped_name, ret_type, wrapper_args, wrapped_args) \
static inline ret_type wrapper_name(wrapper_args) { return (ret_type)wrapped_name(wrapped_args); }

#define def_create_array_args(type) u64 size, allocator_t *alloc, type *array
#define def_array_append_args(type, elem_type) type array, elem_type *elem
#define def_destroy_array_args(type) type array

#define def_create_array_ret int
#define def_array_append_ret int
#define def_destroy_array_ret void

#define def_typed_array(abbrev, type) \
typedef typeof(type)* abbrev ## _array_t; \
def_wrapper_fn(create_ ## abbrev ## _array, create_array, def_create_array_ret, def_create_array_args(abbrev ## _array_t), paste(size, alloc, array, sizeof(**array))) \
def_wrapper_fn(abbrev ## _array_append, array_append, def_array_append_ret, def_array_append_args(abbrev ## _array_t, type), paste(array, elem, sizeof(*array))) \
def_wrapper_fn(destroy_ ## abbrev ## _array, destroy_array, def_destroy_array_ret, def_destroy_array_args(abbrev ## _array_t), paste(array))

struct thing { int x; };

def_typed_array(thing, struct thing)

int main() {
    return 0;
}
#else

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
    create_allocator_arena(NULL, 4096, &alloc);
    
    thing_array_t array;
    create_thing_array(16, &alloc, &array);
    
    for(int i=0; i < cl_array_size(names); ++i) {
        struct thing t;
        t.i = i;
        t.s = names[i];
        t.c = names[i][0];
        thing_array_add(&array, &t);
        println("%u, %u, %s, %c", i, array[i].i, array[i].s, array[i].c);
    }
    
    println("\n\n");
    
    for(int i=0; i < cl_array_size(names); ++i) {
        println("%u, %u, %s, %c", i, array[i].i, array[i].s, array[i].c);
    }
    
    destroy_thing_array(&array);
    
    return 0;
}
#endif