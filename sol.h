#ifndef SOL_H
#define SOL_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <intrin.h>
#include <assert.h>
#include <math.h>
#include <windows.h>

#define SCB_OVERRIDE_STDLIB

#ifdef SCB_OVERRIDE_STDLIB
#undef assert
#define assert scb_assert
#define snprintf scb_snprintf
#define strcpy scb_strcpy
#endif

#define local_persist static
#define internal static

#define dll_export __declspec(dllexport)

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef float f32;
typedef double f64;

typedef u32 b32;

typedef void (*voidpfn)(void);

#define Max_s8  0x7f
#define Max_s16 0x7fff
#define Max_s32 0x7fffffff
#define Max_s64 0x7fffffffffffffff
#define Max_u8  0xff
#define Max_u16 0xffff
#define Max_u32 0xffffffff
#define Max_u64 0xffffffffffffffff

#define ctz(x)      _tzcnt_u64(x)
#define ctz64(x)    _tzcnt_u64(x)
#define ctz32(x)    _tzcnt_u32(x)
#define ctz16(x)    _tzcnt_u16(x)
#define clz(x)      __lzcnt64(x)
#define clz16(x)    __lzcnt16(x)
#define clz32(x)    __lzcnt(x)
#define clz64(x)    __lzcnt64(x)
#define popcnt(x)   __popcnt64(x)
#define popcnt64(x) __popcnt64(x)
#define popcnt32(x) __popcnt32(x)
#define popcnt16(x) __popcnt16(x)

#define typeof(x) __typeof__(x)
#define maxif(x) (0UL - (bool)(x))
#define cl_align(x) __declspec(align(x))
#define cl_array_size(x) (sizeof(x)/sizeof(x[0]))

#define memb_to_struct(memb, memb_of, memb_name) \
((typeof(memb_of))((u8*)memb - offsetof(typeof(*memb_of), memb_name)))

#define memb_size(type, memb) sizeof(((type*)0)->memb)

#define for_bits(pos, count, mask) \
for(count = 0, pos = (typeof(pos))ctz(mask); \
count < popcnt(mask); \
pos = (typeof(pos))ctz((u64)mask & (Max_u64 << (pos + 1))), ++count)

static inline u64 trunc_copy(void *to, u64 to_sz, void *from, u64 from_sz)
{
    if (to_sz < from_sz) {
        memcpy(to, from, to_sz);
        return to_sz;
    }
    memcpy(to, from, from_sz);
    return from_sz;
}

static inline bool is_whitechar(char c)
{
    return c == ' ' || c == '\n' || c == '\t';
}

enum type {
    TYPE_LINEAR,
    TYPE_ARENA,
};

// preproc.h
#define paste(...) __VA_ARGS__
#define stringify(...) #__VA_ARGS__

#define def_wrapper_fn(wrapper_name, wrapped_name, ret_type, wrapper_args, wrapped_args) \
static inline ret_type wrapper_name(wrapper_args) { return (ret_type)wrapped_name(wrapped_args); }

// os.h
extern struct os {
    bool is_valid;
    u32 page_size;
    u32 thread_count;
    HANDLE stdout_handle;
} os;

struct os_process {
    void *p,*t; // process and thread handle
};

#define def_create_os(name) void name(void)
def_create_os(create_os);

#define def_os_error_string(name) void name(char *buf, u32 size)
def_os_error_string(os_error_string);

#define def_os_allocate(name) void* name(u64 size)
def_os_allocate(os_allocate);

#define def_os_deallocate(name) void name(void *p, u64 size)
def_os_deallocate(os_deallocate);

#define def_os_page_size(name) u32 name(void)
def_os_page_size(os_page_size);

#define def_os_stdout(name) HANDLE name(void)
def_os_stdout(os_stdout);

#define def_os_create_lib(name) void* name(char *uri)
def_os_create_lib(os_create_lib);

#define def_os_libproc(name) voidpfn name(void *lib, char *proc)
def_os_libproc(os_libproc);

#define def_os_destroy_lib(name) void name(void *lib)
def_os_destroy_lib(os_destroy_lib);

#define def_os_create_process(name) int name(char *cmdline, struct os_process *p)
def_os_create_process(os_create_process);

#define def_os_await_process(name) int name(struct os_process *p)
def_os_await_process(os_await_process);

#define def_os_destroy_process(name) void name(struct os_process *p)
def_os_destroy_process(os_destroy_process);

#define def_os_sleep_ms(name) void name(u32 ms)
def_os_sleep_ms(os_sleep_ms);

// rc.h
typedef struct rc rc_t;

struct rc {
    u32 count;
};

static inline void rc_init(rc_t *rc)
{
    memset(rc, 0, sizeof(*rc));
}

static inline void rc_inc(rc_t *rc)
{
    
    rc->count += 1;
}

static inline bool rc_dec(rc_t *rc)
{
    rc->count -= rc->count > 0;
    return rc->count;
}

// file.h
#define FILE_ERROR Max_u64

#define def_write_stdout(name) void name(char *buf, u64 size)
def_write_stdout(write_stdout);

#define def_write_file(name) u64 name(char *uri, void *buf, u64 size)
def_write_file(write_file);

#define def_read_file(name) u64 name(char *uri, void *buf, u64 size)
def_read_file(read_file);

#define def_copy_file(name) int name(char *fnew, char *fold)
def_copy_file(copy_file);

#define def_trunc_file(name) int name(char *uri, u64 sz)
def_trunc_file(trunc_file);

#define def_getftim(name) u64 name(char *uri)
def_getftim(getftim);

enum {
    FTIM_MOD,
};
#define def_cmpftim(name) int name(u32 opt, char *x, char *y)
def_cmpftim(cmpftim);

// print.h
#define def_snprintf(name) u32 name(char *buf, u32 size, const char *fmt, ...)
def_snprintf(scb_snprintf);

#define strfmt(str, fmt, ...) scb_snprintf(str.data, (u32)str.size, fmt, __VA_ARGS__)
#define memfmt(buf, sz, fmt, ...) scb_snprintf(buf, sz, fmt, __VA_ARGS__)

#if DEBUG
#define dbg_strfmt strfmt
#else
#define dbg_strfmt(...)
#endif

#define print(fmt, ...) \
do { \
char m__print_buf[2046]; \
u32 m__print_size = scb_snprintf(m__print_buf, sizeof(m__print_buf), fmt, __VA_ARGS__); \
write_stdout(m__print_buf, m__print_size); \
} while(0);

#define println(fmt, ...) \
do { \
char m__println_buf[2046]; \
u32 m__println_size = scb_snprintf(m__println_buf, sizeof(m__println_buf), fmt, __VA_ARGS__); \
m__println_buf[m__println_size++] = '\n'; \
write_stdout(m__println_buf, m__println_size); \
} while(0);

#define print_err(fmt, ...) \
do { \
char m__print_buf[2046]; \
u32 m__print_size = scb_snprintf(m__print_buf, sizeof(m__print_buf), fmt, __VA_ARGS__); \
write_stderr(m__print_buf, m__print_size); \
} while(0);

#define println_err(fmt, ...) \
do { \
char m__println_buf[2046]; \
u32 m__println_size = scb_snprintf(m__println_buf, sizeof(m__println_buf), fmt, __VA_ARGS__); \
m__println_buf[m__println_size++] = '\n'; \
write_stderr(m__println_buf, m__println_size); \
} while(0);

// assert.h
#define scb_assert(x) \
if (!(x)) { \
println("[%s, %s, %u] ASSERT : %s", __FILE__, __FUNCTION__, __LINE__, #x); \
__debugbreak(); \
}


#if DEBUG
#define log_break __debugbreak()

#define log_error(...) \
do { \
print("[%s, %s, %u] LOG ERROR : ", __FILE__, __FUNCTION__, __LINE__); \
println(__VA_ARGS__); \
log_break; \
} while(0);

#define log_os_error(...) \
do { \
char m__log_os_error_buf[512]; \
os_error_string(m__log_os_error_buf, sizeof(m__log_os_error_buf)); \
print("[%s, %s, %u] LOG OS ERROR : ", __FILE__, __FUNCTION__, __LINE__); \
print(__VA_ARGS__); \
println(" : %s", m__log_os_error_buf); \
log_break; \
} while(0);
#else
#define log_error(...)
#define log_os_error(...)
#endif

#define log_error_if(prec, ...) \
do { if (prec) log_error(__VA_ARGS__); } while(0);

#define log_os_error_if(prec, ...) \
do { if (prec) log_os_error(__VA_ARGS__); } while(0);

#define invalid_default_case log_error("Invalid default case")

// math.h
#define kb(x) ((x) * 1024UL)
#define mb(x) (kb(x) * 1024UL)
#define gb(x) (mb(x) * 1024UL)

#define secs_to_ms(x) ((x) * 1000)

struct rect_u32 { u32 w,h; };
struct rect_s32 { s32 w,h; };

static inline bool is_pow2(u64 x)
{
    // NOTE(SollyCB): I know that zero is not a power of two, but this function
    // acts on integers, so any code using it is doing so for alignment and offset purposes,
    // and zero being valid is therefore useful.
    return (x & (x - 1)) == 0;
}

static inline u64 mod_pow2(u64 l, u64 r)
{
    log_error_if(!is_pow2(r), "Trying to align to a value which is not a power of 2");
    return l & (r - 1);
}

static inline u64 next_pow2(u64 x) // TODO(SollyCB): There must be a better implementation...
{
    if (x == 0)
        return 1;
    return is_pow2(x) ? x : (u64)1 << clz(x);
}

static inline u64 inc_and_wrap(u64 inc, u64 wrap)
{
    log_error_if(!is_pow2(wrap), "Wrapping value must be a power of 2");
    return (inc + 1) & (wrap - 1);
}

static inline u64 align(u64 size, u64 alignment) {
    log_error_if(!is_pow2(alignment), "Trying to align to a value which is not a power of 2");
    u64 alignment_mask = alignment - 1;
    return (size + alignment_mask) & ~alignment_mask;
}

static inline u32 log2_u32(u32 x)
{
    u32 c = 0;
    while(x /= 2)
        c += 1;
    return c;
}

static inline u64 set_add(u64 set, u64 i)
{
    log_error_if(i > 64, "Trying to add %u to a set which only holds 64", i);
    return set | ((u64)1 << i);
}

static inline bool set_test(u64 set, u64 i)
{
    return set & ((u64)1 << i);
}

// list.h
typedef struct list list_t;

struct list {
    struct list *next;
    struct list *prev;
};

static inline void create_list(list_t *list)
{
    list->next = list;
    list->prev = list;
}

static inline bool list_is_empty(list_t *list)
{
    return list->next == NULL;
}

static inline void list_add_head(list_t *list, list_t *new_memb)
{
    list_t *next = list->next;
    next->prev = new_memb;
    list->next = new_memb;
    new_memb->prev = list;
    new_memb->next = next;
    if (list->prev == list)
        list->prev = new_memb;
}

static inline void list_add_tail(list_t *list, list_t *new_memb)
{
    list_t *prev = list->prev;
    prev->next = new_memb;
    list->prev = new_memb;
    new_memb->next = list;
    new_memb->prev = prev;
    if (list->next == list)
        list->next = new_memb;
}

static inline bool list_remove(list_t *list)
{
    if (list->next == list->prev)
        return false;
    
    list_t *next = list->next;
    list_t *prev = list->prev;
    next->prev = prev;
    prev->next = next;
    
    return true;
}

#define list_is_end(it, head, memb_name) \
(&it->memb_name == head)

#define list_for_each(it, head, memb_name) \
for(it = memb_to_struct((head)->next, it, memb_name); \
!list_is_end(it, head, memb_name); \
it = memb_to_struct(it->memb_name.next, it, memb_name))

#define list_for_each_rev(it, head, memb_name) \
for(it = memb_to_struct((head)->prev, it, memb_name); \
!list_is_end(it, head, memb_name); \
it = memb_to_struct(it->memb_name.prev, it, memb_name))

#define list_for_each_safe(it, tmp, head, memb_name) \
for(it = memb_to_struct((head)->next, it, memb_name), \
tmp = memb_to_struct(it->memb_name.next, it, memb_name); \
!list_is_end(it, head, memb_name); \
it = tmp, \
tmp = memb_to_struct(it->memb_name.next, it, memb_name))

#define list_for_each_rev_safe(it, tmp, head, memb_name) \
for(it = memb_to_struct((head)->prev, it, memb_name), \
tmp = memb_to_struct(it->memb_name.prev, it, memb_name); \
!list_is_end(it, head, memb_name); \
it = tmp, \
tmp = memb_to_struct(it->memb_name.prev, it, memb_name))

#define list_for(it, head, memb_name, count) \
for(it = memb_to_struct((head)->next, it, memb_name); \
count--; \
it = memb_to_struct(it->memb_name.next, it, memb_name))

#define list_for_rev(it, head, memb_name, count) \
for(it = memb_to_struct((head)->prev, it, memb_name); \
count--; \
it = memb_to_struct(it->memb_name.prev, it, memb_name))

#define list_for_safe(it, tmp, head, memb_name, count) \
for(it = memb_to_struct((head)->next, it, memb_name), \
tmp = memb_to_struct(it->memb_name.next, it, memb_name); \
count--; it = tmp, \
tmp = memb_to_struct(it->memb_name.next, it, memb_name))

#define list_for_rev_safe(it, tmp, head, memb_name, count) \
for(it = memb_to_struct((head)->prev, it, memb_name), \
tmp = memb_to_struct(it->memb_name.prev, it, memb_name); \
count--; it = tmp, \
tmp = memb_to_struct(it->memb_name.prev, it, memb_name))

// alloc.h
typedef struct allocator allocator_t;
typedef struct arena arena_t;
typedef struct linear linear_t;

enum allocator_flags {
    ALLOCATOR_FLAG_FREE_BUFFER = 0x01,
};

struct linear {
    enum allocator_flags flags;
    u64 size;
    u64 used;
    u8 *data;
};

struct arena {
    u32 min_block_size;
    u32 block_count;
    struct list block_list;
};

struct allocator {
    enum type type;
    union {
        arena_t arena;
        linear_t linear;
    };
};

#define alloc_align(size) align(size, 16)

#define def_create_allocator(name, type) int name(void *buf, u64 size, type ## _t *alloc)
def_create_allocator(create_linear, linear);
def_create_allocator(create_arena, arena);

#define def_allocate(name, type) void *name(type ## _t *alloc, u64 size)
def_allocate(linear_allocate, linear);
def_allocate(arena_allocate, arena);

#define def_reallocate(name, type) void *name(type ## _t *alloc, void *old_p, u64 new_size)
def_reallocate(linear_reallocate, linear);
def_reallocate(arena_reallocate, arena);

#define def_allocator_size(name, type) u64 name(type ## _t *alloc)
def_allocator_size(linear_size, linear);
def_allocator_size(arena_size, arena);

#define def_allocator_used(name, type) u64 name(type ## _t *alloc)
def_allocator_used(linear_used, linear);
def_allocator_used(arena_used, arena);

#define def_deallocate(name, type) void name(type ## _t *alloc, void *p)
def_deallocate(linear_deallocate, linear);
def_deallocate(arena_deallocate, arena);

#define def_destroy_allocator(name, type) void name(type ## _t *alloc)
def_destroy_allocator(destroy_linear, linear);
def_destroy_allocator(destroy_arena, arena);

static inline def_create_allocator(create_allocator, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: return create_linear(buf, size, &alloc->linear);
        case TYPE_ARENA: return create_arena(buf, size, &alloc->arena);
        default: invalid_default_case;
    }
    return -1;
}

#define create_allocator_linear(buf, size, alloc) \
do { (alloc)->type = TYPE_LINEAR; create_allocator(buf, size, alloc); } while(0);

#define create_allocator_arena(size, alloc) \
do { (alloc)->type = TYPE_ARENA; create_allocator(NULL, size, alloc); } while(0);

static inline def_allocate(allocate, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: return linear_allocate(&alloc->linear, size);
        case TYPE_ARENA: return arena_allocate(&alloc->arena, size);
        default: invalid_default_case;
    }
    return NULL;
}

static inline def_allocator_size(allocator_size, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: return linear_size(&alloc->linear);
        case TYPE_ARENA: return arena_size(&alloc->arena);
        default: invalid_default_case;
    }
    return Max_u64;
}

static inline def_allocator_used(allocator_used, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: return linear_used(&alloc->linear);
        case TYPE_ARENA: return arena_used(&alloc->arena);
        default: invalid_default_case;
    }
    return Max_u64;
}

static inline def_reallocate(reallocate, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: return linear_reallocate(&alloc->linear, old_p, new_size);
        case TYPE_ARENA: return arena_reallocate(&alloc->arena, old_p, new_size);
        default: invalid_default_case;
    }
    return NULL;
}

static inline def_deallocate(deallocate, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: linear_deallocate(&alloc->linear, p); break;
        case TYPE_ARENA: arena_deallocate(&alloc->arena, p); break;
        default: invalid_default_case;
    }
}

static inline def_destroy_allocator(destroy_allocator, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: destroy_linear(&alloc->linear); break;
        case TYPE_ARENA: destroy_arena(&alloc->arena); break;
        default: invalid_default_case;
    }
}

// string.h
struct string {
    u64 size;
    char *data;
};
#define STR(cstr) ((struct string) { .data = (cstr), .size = strlen(cstr) })
#define CLSTR(buf) ((struct string) { .data = (buf), .size = sizeof(buf) })

typedef struct string_buffer {
    u64 size;
    u64 used;
    char *data;
} string_buffer_t;

typedef struct string_array {
    u32 size;
    u32 used;
    
    struct {
        u64 offset;
        u64 size;
    } *ranges;
    
    string_buffer_t buf;
    allocator_t *alloc;
} string_array_t;

#define def_get_string_buffer(name) void name(char *buf, u64 size, string_buffer_t *ret)
#define def_string_buffer_add(name) int name(string_buffer_t *strbuf, struct string str, struct string *ret)
#define def_string_buffer_add_all(name) int name(string_buffer_t *strbuf, struct string str, struct string *ret)

#define def_create_string_array(name) int name(u64 buf_size, u32 arr_size, allocator_t *alloc, string_array_t *ret)
#define def_string_array_add(name) int name(string_array_t *strarr, struct string str)
#define def_string_array_get(name) int name(string_array_t *strarr, u32 i, struct string *ret)
#define def_string_array_get_raw(name) struct string name(string_array_t *strarr, u32 i)
#define def_destroy_string_array(name) void name(string_array_t *strarr)

def_get_string_buffer(create_string_buffer);
def_string_buffer_add(string_buffer_add);

def_create_string_array(create_string_array);
def_string_array_add(string_array_add);
def_string_array_get(string_array_get);
def_string_array_get_raw(string_array_get_raw);
def_destroy_string_array(destroy_string_array);

// search for, search in
#define def_strfind(name) u32 name(struct string sf, struct string si)
def_strfind(strfind);

#define def_flatten_pchar_array(name) struct string name(char *arr[], u32 arr_sz, char *buf, u32 buf_sz, char sep)
def_flatten_pchar_array(flatten_pchar_array);

static inline u64 scb_strcpy(struct string to, struct string from) {
    return trunc_copy(to.data, to.size, from.data, from.size);
}

static inline u64 strbufcpy(void *buf, u64 buf_sz, struct string from) {
    return trunc_copy(buf, buf_sz, from.data, from.size);
}

// array.h
#define def_create_array_args(type) u64 size, allocator_t *alloc, type *array
#define def_array_add_args(type, elem_type) type *array, elem_type *elem
#define def_array_pop_args(type, elem_type) type *array, elem_type *opt_ret
#define def_array_last_args(type, elem_type) type *array, elem_type *ret
#define def_array_last_raw_args(type, elem_type) type *array
#define def_destroy_array_args(type) type *array

#define def_create_array_ret int
#define def_array_add_ret int
#define def_destroy_array_ret void

#define def_typed_array(abbrev, type) \
typedef typeof(type)* abbrev ## _array_t; \
def_wrapper_fn(create_ ## abbrev ## _array, create_array, def_create_array_ret, def_create_array_args(abbrev ## _array_t), paste(size, alloc, array, sizeof(**array))) \
def_wrapper_fn(abbrev ## _array_add, array_add, def_array_add_ret, def_array_add_args(abbrev ## _array_t, type), paste(array, elem, sizeof(**array))) \
def_wrapper_fn(destroy_ ## abbrev ## _array, destroy_array, def_destroy_array_ret, def_destroy_array_args(abbrev ## _array_t), paste(array, sizeof(**array)))

#define def_create_array(name) def_create_array_ret name(def_create_array_args(void*), u64 stride)
#define def_array_add(name) def_array_add_ret name(def_array_add_args(void*, void), u64 stride)
#define def_destroy_array(name) def_destroy_array_ret name(def_destroy_array_args(void*), u64 stride)

def_create_array(create_array);
def_array_add(array_add);
def_destroy_array(destroy_array);

// dict.h
typedef struct dict dict_t;
typedef struct dict_iter dict_iter_t;

//
// def_typed_dict(abbrev, val_type):
// 
// struct abbrev_dict_kv {
//     u64 key;
//     val_type val;
// };
//
// typedef struct abbrev_dict abbrev_dict_t
// typedef struct abbrev_dict_iter abbrev_dict_iter_t
//
// int create_dict(u64 size, allocator_t *alloc, dict_t *dict)
// int dict_insert(abbrev_dict_t *dict, struct string key, val_type *val)
// bool dict_find(abbrev_dict_t *dict, struct string key, val_type *ret)
// bool dict_remove(dict_t *dict, struct string key)
// void dict_get_iter(dict_t *dict, struct string key)
// bool dict_iter_next(abbrev_dict_t *dict, abbrev_dict_iter_t *iter, val_type *ret)
// void destroy_dict(abbrev_dict_iter_t *iter)
//
// struct thing {
//     u32 i;
//     char *s;
// };
//
// def_typed_dict(thing, struct thing)
//
// void func(u32 size, allocator *alloc, u32 count, struct string *keys, struct thing *things)
// {
//     thing_dict_t dict;
//     if (create_dict(size, alloc, &dict))
//         error;
//
//     for(u32 i=0; i < count; ++i) {
//         if (thing_dict_insert(&dict, keys[i], &things[i]))
//             insertion error;
//     }
//
//     for(u32 i=0; i < count; ++i) {
//         struct thing r;
//         if (!thing_dict_find(&dict, keys[i], &r))
//             doesn't exist;
//     }
//
//     thing_dict_iter_t iter;
//     thing_dict_get_iter(&dict, &iter);
// 
//     struct thing_dict_kv *kv;
//     dict_for_each(kv, &iter, thing_dict_iter_next) {
//         println("key %u, thing.s %s", kv->key, kv->val.s)
//     }
// 
//     destroy_thing_dict(&dict);
// }
//

#define create_typed_dict_args(dict_type) u64 size, allocator_t *alloc, dict_type *dict
#define create_typed_dict_ret() int

#define typed_dict_insert_args(dict_type, value_type) dict_type *dict, struct string key, value_type *val
#define typed_dict_insert_ret() int

#define typed_dict_find_args(dict_type, ret_type) dict_type *dict, struct string key, ret_type *ret
#define typed_dict_find_ret() bool

#define typed_dict_remove_args(dict_type) dict_type *dict, struct string key
#define typed_dict_remove_ret() bool

#define typed_dict_get_iter_args(dict_type, dict_iter_type) dict_type *dict, dict_iter_type *iter
#define typed_dict_get_iter_ret() void

#define typed_dict_iter_next_args(dict_iter_type, ret_type) dict_iter_type *iter, ret_type *ret
#define typed_dict_iter_next_ret() bool

#define typed_dict_destroy_args(dict_type) dict_type *dict
#define typed_dict_destroy_ret() void

#define def_create_dict(name) int name(u64 size, u64 stride, allocator_t *alloc, dict_t *dict)
#define def_dict_insert(name) int dict_insert(dict_t *dict, struct string key, void *val, u64 stride)
#define def_dict_find(name) bool dict_find(dict_t *dict, struct string key, u64 stride, void *ret)
#define def_dict_remove(name) bool dict_remove(dict_t *dict, struct string key, u64 stride)
#define def_dict_get_iter(name) void dict_get_iter(dict_t *dict, dict_iter_t *iter)
#define def_dict_iter_next(name) bool dict_iter_next(dict_iter_t *iter, u64 stride, void *ret)
#define def_destroy_dict(name) void destroy_dict(dict_t *dict, u64 stride)

def_create_dict(create_dict);
def_dict_insert(dict_insert);
def_dict_find(dict_find);
def_dict_remove(dict_remove);
def_dict_get_iter(dict_get_iter);
def_dict_iter_next(dict_iter_next);
def_destroy_dict(destroy_dict);

#define def_get_dict_key(name) u64 name(struct string key)
def_get_dict_key(get_dict_key);

#define dict_for_each(kv, dict_iter, func) \
while(func(dict_iter, kv))

#define def_dict_kv(name, type) \
struct name { \
u64 key; \
type val; \
};

#define def_dict(name, kv_name) \
typedef struct name { \
u32 cap; \
u32 rem; \
kv_name *data; \
allocator_t *alloc; \
} name ## _t;

#define def_dict_iter(name, dict_name) \
typedef struct name { \
dict_name *dict; \
u32 pos; \
} name ## _t;

#define def_typed_dict(abbrev, value) \
def_dict_kv(abbrev ## _dict_kv, typeof(value)) \
def_dict(abbrev ## _dict, struct abbrev ## _dict_kv) \
def_dict_iter(abbrev ## _dict_iter, abbrev ## _dict_t) \
def_wrapper_fn(create_ ## abbrev ## _dict, create_dict, create_typed_dict_ret(), create_typed_dict_args(abbrev ## _dict_t), paste(size, sizeof(*dict->data), alloc, (dict_t*)dict)) \
def_wrapper_fn(abbrev ## _dict_insert, dict_insert, typed_dict_insert_ret(), typed_dict_insert_args(abbrev ## _dict_t, typeof(value)), paste((dict_t*)dict, key, val, sizeof(*dict->data))) \
def_wrapper_fn(abbrev ## _dict_find, dict_find, typed_dict_find_ret(), typed_dict_find_args(abbrev ## _dict_t, typeof(value)), paste((dict_t*)dict, key, sizeof(*dict->data), ret)) \
def_wrapper_fn(abbrev ## _dict_remove, dict_remove, typed_dict_remove_ret(), typed_dict_remove_args(abbrev ## _dict_t), paste((dict_t*)dict, key, sizeof(*dict->data))) \
def_wrapper_fn(abbrev ## _dict_get_iter, dict_get_iter, typed_dict_get_iter_ret(), typed_dict_get_iter_args(abbrev ## _dict_t, abbrev ## _dict_iter_t), paste((dict_t*)dict, (dict_iter_t*)iter)) \
def_wrapper_fn(abbrev ## _dict_iter_next, dict_iter_next, typed_dict_iter_next_ret(), typed_dict_iter_next_args(abbrev ## _dict_iter_t, typeof(value)), paste((dict_iter_t*)iter, sizeof(*iter->dict->data), ret)) \
def_wrapper_fn(destroy_ ## abbrev ## _dict, destroy_dict, typed_dict_destroy_ret(), typed_dict_destroy_args(abbrev ## _dict_t), paste((dict_t*)dict, sizeof(*dict->data)))

#ifdef SOL_DEF

// os.c
struct os os;

def_create_os(create_os)
{
    assert(os.is_valid == false);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    os.page_size = si.dwPageSize;
    os.stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    os.thread_count = si.dwNumberOfProcessors;
}

def_os_error_string(os_error_string)
{
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, buf, size, NULL);
}

def_os_allocate(os_allocate)
{
    void *p = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    log_error_if(!p, "Failed to allocate %u bytes from OS", size);
    return p;
}

def_os_deallocate(os_deallocate)
{
    bool b = VirtualFree(p, 0, MEM_RELEASE);
    log_os_error_if(!b, "Failed to free address %u", p);
}

def_os_page_size(os_page_size)
{
    if (!os.is_valid)
        create_os();
    return os.page_size;
}

def_os_stdout(os_stdout)
{
    if (!os.is_valid)
        create_os();
    return os.stdout_handle;
}

def_os_create_lib(os_create_lib)
{
    return LoadLibrary(uri);
}

def_os_libproc(os_libproc)
{
    return (voidpfn)GetProcAddress(lib, proc);
}

def_os_destroy_lib(os_destroy_lib)
{
    FreeLibrary(lib);
}

def_os_create_process(os_create_process)
{
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcess(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        log_os_error("Failed to create process with command %s", cmdline);
        return -1;
    }
    
    p->p = pi.hProcess;
    p->t = pi.hThread;
    return 0;
}

def_os_await_process(os_await_process)
{
    WaitForSingleObject(p->p, INFINITE);
    
    int res;
    if (!GetExitCodeProcess(p->p, (LPDWORD)&res)) {
        log_error("Failed to get process exit code");
        return Max_s32;
    }
    
    return res;
}

def_os_destroy_process(os_destroy_process)
{
    CloseHandle(p->p);
    CloseHandle(p->t);
}

def_os_sleep_ms(os_sleep_ms)
{
    Sleep(ms);
}

// file.c
enum {
    FILE_READ = 0x0,
    FILE_WRITE = 0x01,
    FILE_CREATE = 0x02,
};

def_write_stdout(write_stdout)
{
    WriteFile(os_stdout(), buf, (u32)size, NULL, NULL);
}

def_write_file(write_file)
{
    u32 res = 0;
    HANDLE fd = CreateFile(uri, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        log_os_error("Failed to open file %s", uri);
        return FILE_ERROR;
    }
    
    BOOL success = WriteFile(fd, buf, (u32)size, (LPDWORD)&res, NULL);
    if (!success) {
        log_os_error("Failed to write file %s", uri);
        CloseHandle(fd);
        return FILE_ERROR;
    }
    
    CloseHandle(fd);
    return res;
}

def_read_file(read_file)
{
    if (!buf) {
        WIN32_FIND_DATA info;
        HANDLE fd = FindFirstFile(uri, &info);
        
        if (fd == INVALID_HANDLE_VALUE) {
            log_os_error("Failed to find file %s", uri);
            return FILE_ERROR;
        }
        
        FindClose(fd);
        return info.nFileSizeLow;
    }
    
    u32 res = 0;
    HANDLE fd = CreateFile(uri, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (fd == INVALID_HANDLE_VALUE) {
        log_os_error("Failed to open file %s", uri);
        return FILE_ERROR;
    }
    
    BOOL success = ReadFile(fd, buf, (u32)size, (LPDWORD)&res, NULL);
    if (!success) {
        log_os_error("Failed to read file %s", uri);
        CloseHandle(fd);
        return FILE_ERROR;
    }
    
    CloseHandle(fd);
    return res;
}

def_copy_file(copy_file)
{
    if (!CopyFile(fold, fnew, false)) {
        log_os_error("Failed to copy from %s to %s", fnew, fold);
        return -1;
    }
    return 0;
}

def_trunc_file(trunc_file)
{
    int res = 0;
    
    HANDLE h = CreateFile(uri, GENERIC_READ|GENERIC_WRITE,
                          0, NULL, CREATE_ALWAYS, 0, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        log_error("Failed to open file for truncation (%s)", uri);
        res = -1;
        goto out;
    }
    
    FILE_END_OF_FILE_INFO fi = {.EndOfFile = (DWORD)sz};
    
    if (!SetFileInformationByHandle(h, FileEndOfFileInfo, &fi, sizeof(fi))) {
        log_error("Failed to truncate file %s to size %u", uri, sz);
        res = -1;
        goto out;
    }
    
    out:
    CloseHandle(h);
    return res;
}

def_getftim(getftim)
{
    WIN32_FIND_DATA d;
    if (FindFirstFile(uri, &d) == INVALID_HANDLE_VALUE) {
        log_error("Failed to stat file %s", uri);
        return Max_u64;
    }
    
    ULARGE_INTEGER li; // Fuck this api...
    li.LowPart = d.ftLastWriteTime.dwLowDateTime;
    li.HighPart = d.ftLastWriteTime.dwHighDateTime;
    return li.QuadPart;
}

def_cmpftim(cmpftim)
{
    u64 tx = getftim(x);
    u64 ty = getftim(y);
    
    if (tx == Max_u64 || ty == Max_u64) {
        log_error("Failed to get file times for comparison");
        return Max_s32;
    }
    
    switch(opt) {
        case FTIM_MOD: {
            if (tx < ty) return -1;
            if (tx > ty) return 1;
            return 0;
        } break;
        default:
        invalid_default_case;
    }
    return Max_s32;
}

// print.c
enum {
    PR_I = 0x01,
    PR_U = 0x02,
    PR_S = 0x04,
    PR_F = 0x08,
    PR_C = 0x10,
    PR_B = 0x20,
    PR_H = 0x40,
    PR_Z = 0x80,
};

#define def_pr_parse(name, type) static u32 name(char *buf, u32 size, type x, u32 f)

def_pr_parse(pr_parse_u, u64)
{
    u32 bp = 0;
    u32 zc = 0;
    char tmp[128];
    
    if (x == 0)
        tmp[bp++] = '0';
    
    if (f & PR_Z) {
        zc = clz64(x) & maxif(popcnt(x));
        if (f & PR_H)
            zc /= 4;
    }
    if (f & PR_H) {
        while(x > 0) {
            char b = (char)x & 0xf;
            if (b > 9)
                tmp[bp++] = 'a' + (b - 10);
            else
                tmp[bp++] = b + '0';
            x >>= 4;
        }
    } else if (f & PR_B) {
        while(x > 0) {
            tmp[bp++] = (x & 0x1) + '0';
            x >>= 1;
        }
    } else {
        while(x > 0) {
            tmp[bp++] = (x % 10) + '0';
            x /= 10;
        }
    }
    if (f & (PR_H|PR_B)) {
        while(zc--)
            tmp[bp++] = '0';
        tmp[bp++] = f & PR_H ? 'x' : 'b';
        tmp[bp++] = '0';
    }
    u32 ti = bp;
    if (bp > size)
        bp = size;
    for(u32 i=0; i < bp; ++i)
        buf[i] = tmp[ti-1-i];
    return bp;
}

def_pr_parse(pr_parse_i, s64)
{
    u32 bp = 0;
    if (x < 0) {
        if (size == 0)
            return 0;
        buf[bp++] = '-';
        x *= -1;
    }
    bp += pr_parse_u(buf + bp, size, x, f);
    return bp;
}

def_pr_parse(pr_parse_s, char*)
{
    u32 bp = (u32)strlen(x);
    if (bp > size)
        bp = size;
    memcpy(buf, x, bp);
    return bp;
}

def_pr_parse(pr_parse_f, f64)
{
    // TODO(SollyCB): Idk if I will ever get round to implementing this myself...
    u32 bp = snprintf(buf, size, "%f", x);
    return bp;
}

def_pr_parse(pr_parse_c, char)
{
    if (size == 0)
        return 0;
    buf[0] = x;
    return 1;
}

static inline bool pr_is_ident(char c)
{
    switch(c) {
        case 'i':
        case 'u':
        case 's':
        case 'f':
        case 'c':
        case 'b':
        case 'h':
        case 'z':
        return true;
        default:
        return false;
    }
}

def_snprintf(scb_snprintf)
{
    va_list va;
    va_start(va, fmt);
    u32 f = 0;
    u32 bp = 0;
    u32 sl = (u32)strlen(fmt);
    for(u32 i=0; i < sl && bp < size-1; ++i) {
        f = 0;
        switch(fmt[i]) {
            case '-': {
                if (i < sl-1 && fmt[i+1] == '%') {
                    buf[bp++] = fmt[i+1];
                    ++i;
                    continue;
                }
            } break;
            case '%': {
                ++i;
                for(; i < sl && pr_is_ident(fmt[i]); ++i) {
                    f |= PR_I & maxif(fmt[i] == 'i');
                    f |= PR_U & maxif(fmt[i] == 'u');
                    f |= PR_S & maxif(fmt[i] == 's');
                    f |= PR_F & maxif(fmt[i] == 'f');
                    f |= PR_C & maxif(fmt[i] == 'c');
                    f |= PR_B & maxif(fmt[i] == 'b');
                    f |= PR_H & maxif(fmt[i] == 'h');
                    f |= PR_Z & maxif(fmt[i] == 'z');
                }
                --i;
            } break;
            default:
            buf[bp++] = fmt[i];
        }
        if (f & PR_I) {
            s64 x = va_arg(va, s64);
            bp += pr_parse_i(buf + bp, size - bp - 1, x, f);
        } else if (f & PR_U) {
            u64 x = va_arg(va, u64);
            bp += pr_parse_u(buf + bp, size - bp - 1, x, f);
        } else if (f & PR_S) {
            char *x = va_arg(va, char*);
            bp += pr_parse_s(buf + bp, size - bp - 1, x, f);
        } else if (f & PR_F) {
            double x = va_arg(va, double);
            bp += pr_parse_f(buf + bp, size - bp - 1, x, f);
        } else if (f & PR_C) {
            char x = va_arg(va, char);
            bp += pr_parse_c(buf + bp, size - bp - 1, x, f);
        }
    }
    va_end(va);
    buf[bp++] = 0;
    return bp;
}

// alloc.c
#define ALLOC_INFO_GUARD 0xcafe6969feedbeef

struct alloc_info {
    u64 guard;
    u64 size;
};

struct arena_header {
    u64 validation_bits;
    linear_t linear;
    list_t list;
    rc_t rc;
};

// TODO(SollyCB): READ THROUGH THE ARENA ALLOCATOR FUNCTIONS!!! I ran into problems with them
// before as I had clearly rushed the implementations.
#define ARENA_HEADER_SIZE align(sizeof(struct arena_header), 16)
#define ARENA_VALIDATION_BITS 0xcafebabecafebabe

static inline u64 alloc_check_guard_and_get_size(void *p)
{
    struct alloc_info *info = (typeof(info))p - 1;
    log_error_if(info->guard != ALLOC_INFO_GUARD, "Allocation guard was corrupted or address is not a valid allocation");
    return info->size;
}

static inline void alloc_info_new_size(void *p, u64 size)
{
    struct alloc_info *info = (typeof(info))p - 1;
    info->size = size;
}

static inline bool linear_is_top(linear_t *alloc, void *p, u64 size)
{
    return p == alloc->data + alloc->used - alloc_align(size);
}

static inline bool arena_header_is_valid(struct arena_header *header)
{
    return header->validation_bits == ARENA_VALIDATION_BITS;
}

static struct arena_header* create_arena_block(arena_t *alloc, u64 size)
{
    u64 block_size = align(size + ARENA_HEADER_SIZE, os_page_size());
    if (block_size < alloc->min_block_size)
        block_size = alloc->min_block_size;
    
    void *p = os_allocate(block_size);
    if (!p)
        return NULL;
    
    struct arena_header *block = p;
    void *mem = block + 1;
    
    memset(block, 0, sizeof(*block));
    block->validation_bits = ARENA_VALIDATION_BITS;
    create_linear(mem, block_size - ARENA_HEADER_SIZE, &block->linear);
    
    alloc->block_count += 1;
    return block;
}

static void destroy_arena_block(arena_t *alloc, struct arena_header *block)
{
    list_remove(&block->list);
    os_deallocate(block->linear.data, block->linear.size + ARENA_HEADER_SIZE);
    alloc->block_count -= alloc->block_count > 0;
}

struct arena_header* arena_find_block(arena_t *alloc, void *p)
{
    struct arena_header *block;
    u32 count = alloc->block_count;
    list_for(block, &alloc->block_list, list, count) {
        if ((u8*)p >= block->linear.data &&
            (u8*)p < block->linear.data + block->linear.size)
            break;
    }
    log_error_if(list_is_end(block, &alloc->block_list, list),
                 "Failed to find block containing address %u", p);
    return block;
}

static void* arena_header_allocate(struct arena_header *block, u64 size)
{
    log_error_if(!arena_header_is_valid(block), "Failed to validate arena header");
    void *p = linear_allocate(&block->linear, size);
    if (p)
        rc_inc(&block->rc);
    return p;
}

static void arena_header_deallocate(arena_t *alloc, struct arena_header *block, void *p)
{
    log_error_if(!arena_header_is_valid(block), "Failed to validate arena header");
    if (!rc_dec(&block->rc)) {
        destroy_arena_block(alloc, block);
        return;
    }
    linear_deallocate(&block->linear, p);
}

def_create_allocator(create_linear, linear)
{
    size = alloc_align(size);
    
    if (!buf) {
        buf = os_allocate(size);
        if (!buf)
            return -1;
    }
    
    alloc->data = buf;
    alloc->size = size;
    alloc->used = 0;
    return 0;
}

def_allocate(linear_allocate, linear)
{
    struct alloc_info *info;
    size = alloc_align(size);
    if (alloc->size < alloc->used + size + sizeof(*info))
        return NULL;
    
    info = (typeof(info))(alloc->data + alloc->used);
    info->guard = ALLOC_INFO_GUARD;
    info->size = size;
    
    alloc->used += size + sizeof(*info);
    return alloc->data + alloc->used - size;
}

def_reallocate(linear_reallocate, linear)
{
    u64 old_size = alloc_check_guard_and_get_size(old_p);
    new_size = alloc_align(new_size);
    
    if (linear_is_top(alloc, old_p, old_size)) {
        log_error_if(new_size < old_size && old_size - new_size > alloc->used, "Allocator underflow");
        log_error_if(new_size > old_size && new_size - old_size > alloc->size - alloc->used, "Allocator overflow");
        
        alloc->used += (s64)new_size - (s64)old_size;
        alloc_info_new_size(old_p, new_size);
        return old_p;
    }
    
    if (new_size < old_size)
        return old_p;
    
    void *p = linear_allocate(alloc, new_size);
    if (p)
        memcpy(p, old_p, old_size);
    
    return p;
}

def_allocator_size(linear_size, linear)
{
    return alloc->size;
}

def_allocator_used(linear_used, linear)
{
    return alloc->used;
}

def_deallocate(linear_deallocate, linear)
{
    u64 size = alloc_check_guard_and_get_size(p);
    if (linear_is_top(alloc, p, size))
        alloc->used -= alloc_align(size) + sizeof(struct alloc_info);
}

def_destroy_allocator(destroy_linear, linear)
{
    if (alloc->flags & ALLOCATOR_FLAG_FREE_BUFFER)
        os_deallocate(alloc->data, alloc->size);
    memset(alloc, 0, sizeof(*alloc));
}

def_create_allocator(create_arena, arena)
{
    log_error_if(size > Max_u32, "minimum arena block size cannot be greater than 4GB");
    alloc->min_block_size = (u32)size;
    alloc->block_count = 0;
    create_list(&alloc->block_list);
    return 0;
}

def_allocate(arena_allocate, arena)
{
    size = alloc_align(size);
    
    struct arena_header *block;
    u32 count = alloc->block_count;
    
    list_for(block, &alloc->block_list, list, count) {
        void *p = arena_header_allocate(block, size);
        if (p)
            return p;
    }
    
    block = create_arena_block(alloc, size);
    if (!block)
        return NULL;
    
    list_add_tail(&alloc->block_list, &block->list);
    return arena_header_allocate(block, size);
}

def_reallocate(arena_reallocate, arena)
{
    u64 old_size = alloc_check_guard_and_get_size(old_p);
    
    void *p;
    struct arena_header *block = arena_find_block(alloc, old_p);
    
    if (linear_is_top(&block->linear, old_p, old_size)) {
        p = linear_reallocate(&block->linear, old_p, new_size);
        if (p)
            return p;
    }
    
    p = arena_allocate(alloc, new_size);
    if (p) {
        memcpy(p, old_p, old_size);
        arena_header_deallocate(alloc, block, old_p);
    }
    return p;
}

def_allocator_size(arena_size, arena)
{
    u64 size = 0;
    u32 count = alloc->block_count;
    struct arena_header *block;
    
    list_for(block, &alloc->block_list, list, count)
        size += align(linear_size(&block->linear) + ARENA_HEADER_SIZE, os_page_size());
    
    return size;
}

def_allocator_used(arena_used, arena)
{
    u64 size = 0;
    u32 count = alloc->block_count;
    struct arena_header *block;
    
    list_for(block, &alloc->block_list, list, count)
        size += linear_used(&block->linear);
    
    return size;
}

def_deallocate(arena_deallocate, arena)
{
    struct arena_header *block = arena_find_block(alloc, p);
    arena_header_deallocate(alloc, block, p);
}

def_destroy_allocator(destroy_arena, arena)
{
    struct arena_header *block, *tmp;
    list_for_safe(block, tmp, &alloc->block_list, list, alloc->block_count) {
        list_remove(&block->list);
        destroy_arena_block(alloc, block);
    }
}

// string.c
def_get_string_buffer(get_string_buffer)
{
    ret->data = buf;
    ret->size = size;
    ret->used = 0;
}

def_string_buffer_add(string_buffer_add)
{
    log_error_if(strbuf->size < strbuf->used, "string_buffer overflowed");
    if (strbuf->size <= strbuf->used)
        return -1;
    
    int res = 0;
    if (strbuf->size < strbuf->used + str.size + 1) {
        res = -1;
        str.size = strbuf->size - strbuf->used - 1;
    }
    
    ret->data = strbuf->data + strbuf->used;
    ret->size = str.size;
    strbuf->used += str.size + 1;
    
    memcpy(ret->data, str.data, ret->size);
    ret->data[ret->size] = 0;
    
    return res;
}

def_string_buffer_add_all(string_buffer_add_all)
{
    log_error_if(strbuf->size < strbuf->used, "string_buffer overflowed");
    
    if (strbuf->size < strbuf->used + str.size + 1) {
        memset(ret, 0, sizeof(*ret));
        return -1;
    }
    
    ret->data = strbuf->data + strbuf->used;
    ret->size = str.size;
    strbuf->used += str.size + 1;
    
    memcpy(ret->data, str.data, ret->size);
    ret->data[ret->size] = 0;
    
    return 0;
}

def_create_string_array(create_string_array)
{
    char *buf = allocate(alloc, buf_size);
    if (!buf) {
        log_error("Failed to allocate memory for buffer");
        return -1;
    }
    
    ret->ranges = allocate(alloc, sizeof(*ret->ranges) * arr_size);
    if (!ret->ranges) {
        log_error("Failed to allocate memory for ranges array");
        deallocate(alloc, buf);
        return -1;
    }
    
    ret->size = arr_size;
    ret->used = 0;
    ret->alloc = alloc;
    get_string_buffer(buf, buf_size, &ret->buf);
    
    return 0;
}

def_string_array_add(string_array_add)
{
    log_error_if(strarr->size < strarr->used, "Overflowed");
    if (strarr->size == strarr->used) {
        u64 size = sizeof(*strarr->ranges) * strarr->size;
        void *ranges = reallocate(strarr->alloc, strarr->ranges, size * 2);
        
        if (!ranges) {
            log_error("Failed to grow ranges array");
            return -1;
        }
        
        strarr->ranges = ranges;
        strarr->size *= 2;
    }
    
    struct string ret;
    if (string_buffer_add_all(&strarr->buf, str, &ret)) {
        u64 new_size = strarr->buf.size * 2 + str.size + 1;
        char *buf = reallocate(strarr->alloc, strarr->buf.data, new_size);
        if (!buf) {
            log_error("Failed to grow buffer");
            return -1;
        }
        
        strarr->buf.data = buf;
        strarr->buf.size = new_size;
        string_buffer_add_all(&strarr->buf, str, &ret);
        log_error_if(!ret.data, "Failed to add string to expanded buffer (but this should be impossible!)");
    }
    
    strarr->ranges[strarr->used].offset = (u64)(ret.data - strarr->buf.data);
    strarr->ranges[strarr->used].size = ret.size;
    strarr->used += 1;
    
    return 0;
}

def_string_array_get(string_array_get)
{
    log_error_if(strarr->used == 0, "Indexing empty array");
    log_error_if(strarr->used <= i, "Out of bounds access - max valid index %u, but got %u",
                 strarr->used - 1, i);
    
    if (!ret->data) {
        ret->size = strarr->ranges[i].size;
        return 0;
    }
    
    ret->size = trunc_copy(ret->data, ret->size,
                           strarr->buf.data + strarr->ranges[i].offset,
                           strarr->ranges[i].size);
    ret->data[ret->size] = 0;
    
    return ret->size < strarr->ranges[i].size ? -1 : 0;
}

def_string_array_get_raw(string_array_get_raw)
{
    log_error_if(strarr->used == 0, "Indexing empty array");
    log_error_if(strarr->used <= i, "Out of bounds access - max valid index %u, but got %u",
                 strarr->used - 1, i);
    return (struct string) {.data = strarr->buf.data + strarr->ranges[i].offset, .size = strarr->ranges[i].size};
}

def_destroy_string_array(destroy_string_array)
{
    deallocate(strarr->alloc, strarr->ranges);
    deallocate(strarr->alloc, strarr->buf.data);
    memset(strarr, 0, sizeof(*strarr));
}

def_strfind(strfind)
{
    if (si.size < sf.size)
        return Max_u32;
    
    for(u32 i=0; i < si.size - sf.size; ++i) {
        if (memcmp(si.data + i, sf.data, sf.size) == 0)
            return i;
    }
    
    return Max_u32;
}

def_flatten_pchar_array(flatten_pchar_array)
{
    struct string str = {.data = buf, .size = 0};
    buf_sz -= 1; // null term
    
    for(u32 i=0; i < arr_sz && str.size < buf_sz; ++i) {
        str.size += trunc_copy(buf + str.size, buf_sz - str.size, arr[i], strlen(arr[i]));
        if (str.size == buf_sz)
            break;
        str.data[str.size++] = sep;
    }
    
    str.data[str.size] = 0;
    return str;
}

// array.c
typedef struct array {
    u64 size;
    u64 used;
    void *data;
    allocator_t *alloc;
} array_t;

#define ARRAY_MIN_SIZE 16

def_create_array(create_array)
{
    if (size < ARRAY_MIN_SIZE)
        size = ARRAY_MIN_SIZE;
    
    array_t *tmp = allocate(alloc, size * stride + sizeof(*tmp));
    if (!tmp) {
        log_error("Failed to allocate memory for tmp");
        return -1;
    }
    
    tmp->used = 0;
    tmp->size = size;
    tmp->data = tmp + 1;
    tmp->alloc = alloc;
    *array = tmp->data;
    
    return 0;
}

def_array_add(array_add)
{
    array_t *tmp = ((array_t*) *array) - 1;
    log_error_if(tmp->used > tmp->size, "Array overflowed");
    
    if (tmp->used == tmp->size) {
        array_t old = *tmp;
        tmp = reallocate(tmp->alloc, tmp, sizeof(*tmp) + tmp->size * stride * 2);
        if (!tmp) {
            log_error("Failed to reallocate array");
            return -1;
        }
        tmp->data = tmp + 1;
        tmp->size = old.size * 2;
        *array = tmp->data;
    }
    
    memcpy((u8*)tmp->data + tmp->used * stride, elem, stride);
    tmp->used += 1;
    return 0;
}

def_destroy_array(destroy_array)
{
    array_t *tmp = ((array_t*) *array) - 1;
    deallocate(tmp->alloc, tmp);
    *array = NULL;
}

// dict.c
#define DICT_VALUE_PLACHOLDER u64
def_dict(dict, u8)
def_dict_kv(dict_kv, DICT_VALUE_PLACHOLDER)
def_dict_iter(dict_iter, dict_t)

typedef struct dict_probe {
    dict_t *dict;
    u32 pos;
    u32 stride;
} dict_probe_t;

enum {
    DICT_EMPTY = 0x0,
    DICT_FULL = 0x80,
};

#define DICT_GROUP_SIZE 16
#define DICT_HASH_SIZE 8

#define dict_probe_loop(idx, probe) \
for(idx = dict_probe_next(probe); idx != Max_u32; idx = dict_probe_next(probe))

#define dict_iter_for_each_internal(it, kv, stride, func) \
for(kv = func(it, stride); kv; kv = func(it, stride))

#define def_dict_insert_hash(name) static int name(dict_t *dict, u64 key, void *val, u64 stride)
def_dict_insert_hash(dict_insert_hash);

static inline u8 dict_top7(u64 key)
{
    return (u8)(key >> 57);
}

static inline u32 dict_group(dict_t *dict, u64 key)
{
    u32 i = (u32)mod_pow2(key, dict->cap);
    return i - (u32)mod_pow2(i, DICT_GROUP_SIZE);
}

static inline u32 dict_next_group(u32 pos)
{
    return pos + DICT_GROUP_SIZE - (u32)mod_pow2(pos, DICT_GROUP_SIZE);
}

static inline u32 dict_next_full_slot(dict_t *dict, u32 pos)
{
    if (pos >= dict->cap)
        return Max_u32;
    __m128i a = _mm_load_si128((__m128i*)(dict->data + dict_group(dict, pos)));
    u16 mask = (u16)_mm_movemask_epi8(a);
    mask >>= mod_pow2(pos, DICT_GROUP_SIZE);
    return mask ? pos + (u32)ctz(mask) : Max_u32;
}

static inline u32 dict_next_empty_slot(dict_t *dict, u32 pos)
{
    __m128i a = _mm_load_si128((__m128i*)(dict->data + dict_group(dict, pos)));
    u16 mask = ~(u16)_mm_movemask_epi8(a);
    mask &= 0xffff << mod_pow2(pos, DICT_GROUP_SIZE);
    return mask ? pos + (u32)ctz(mask) : Max_u32;
}

static inline u16 dict_match(dict_t *dict, u32 group, u8 bits)
{
    log_error_if(mod_pow2(group, DICT_GROUP_SIZE), "Group must be a multiple of 16");
    __m128i a = _mm_load_si128((__m128i*)(dict->data + group));
    __m128i b = _mm_set1_epi8(bits);
    a = _mm_cmpeq_epi8(a, b);
    return (u16)_mm_movemask_epi8(a);
}

u64 rapidhash(void *key, u64 len);

static void dict_get_probe(dict_t *dict, u32 start, dict_probe_t *probe)
{
    probe->dict = (dict_t*)dict;
    probe->pos = start;
    probe->stride = 0;
}

static u32 dict_probe_next(dict_probe_t *probe)
{
    if (probe->stride >= probe->dict->cap)
        return Max_u32;
    
    probe->pos = (u32)mod_pow2(probe->pos + probe->stride, probe->dict->cap);
    probe->stride += DICT_GROUP_SIZE;
    return probe->pos;
}

static void* dict_iter_next_internal(dict_iter_t *iter, u64 stride)
{
    u32 i;
    while(1) {
        if (iter->pos >= iter->dict->cap)
            return NULL;
        
        i = dict_next_full_slot(iter->dict, iter->pos);
        if (i != Max_u32)
            break;
        
        iter->pos = dict_next_group(iter->pos);
    }
    iter->pos = i + 1;
    return iter->dict->data + iter->dict->cap + stride * i;
}

static int dict_copy(dict_t *new_dict, dict_t *old_dict, u64 stride)
{
    dict_iter_t it;
    dict_get_iter(old_dict, &it);
    
    struct dict_kv *kv;
    dict_iter_for_each_internal(&it, kv, stride, dict_iter_next_internal) {
        if (dict_insert_hash(new_dict, kv->key, &kv->val, stride))
            return -1;
    }
    return 0;
}

static u32 dict_find_hash(dict_t *dict, u64 key, u64 stride)
{
    dict_probe_t probe;
    dict_get_probe(dict, dict_group(dict, key), &probe);
    
    u32 gr;
    dict_probe_loop(gr, &probe) {
        u16 mask = dict_match(dict, gr, DICT_FULL | dict_top7(key));
        
        if (!mask)
            continue;
        
        u32 i,cnt;
        for_bits(i, cnt, mask) {
            if (key == *(u64*)(dict->data + dict->cap + stride * (gr + i)))
                return gr + i;
        }
    }
    return Max_u32;
}

def_create_dict(create_dict)
{
    dict->cap = (u32)align(align(size, 16), next_pow2(size));
    dict->data = allocate(alloc, dict->cap + dict->cap * stride);
    
    if (!dict->data) {
        log_error("Failed to allocate memory for dict");
        return -1;
    }
    
    memset(dict->data, 0, dict->cap);
    dict->rem = dict->cap / 8 * 7;
    dict->alloc = alloc;
    return 0;
}

def_dict_insert_hash(dict_insert_hash)
{
    if (dict->rem == 0) {
        dict_t old_dict = *dict;
        if (create_dict(dict->cap * 2, stride, dict->alloc, dict) ||
            dict_copy(dict, &old_dict, stride))
        {
            log_error("Failed to initialize new dict on resize");
            *dict = old_dict;
            return -1;
        }
        destroy_dict(&old_dict, stride);
    }
    
    dict_probe_t probe;
    dict_get_probe(dict, dict_group(dict, key), &probe);
    
    u32 gr;
    dict_probe_loop(gr, &probe) {
        u32 i = dict_next_empty_slot(dict, gr);
        if (i != Max_u32) {
            u8 *slot = dict->data + i;
            *slot = DICT_FULL | dict_top7(key);
            
            struct dict_kv *kv = (typeof(kv))(dict->data + dict->cap + stride * i);
            kv->key = key;
            
            void *v = &kv->val;
            memcpy(v, val, stride - DICT_HASH_SIZE);
            
            dict->rem -= 1;
            return 0;
        }
    }
    log_error("Failed to find empty slot");
    return -1;
}

def_get_dict_key(get_dict_key)
{
    return rapidhash(key.data, key.size);
}

def_dict_insert(dict_insert)
{
    return dict_insert_hash(dict, rapidhash(key.data, key.size), val, stride);
}

def_dict_find(dict_find)
{
    u32 i = dict_find_hash(dict, rapidhash(key.data, key.size), stride);
    if (i == Max_u32)
        return false;
    
    memcpy(ret, dict->data + dict->cap + stride * i + DICT_HASH_SIZE, stride - DICT_HASH_SIZE);
    return true;
}

def_dict_remove(dict_remove)
{
    u32 i = dict_find_hash(dict, rapidhash(key.data, key.size), stride);
    
    if (i == Max_u32)
        return false;
    
    u8 *slot = dict-> data + i;
    *slot = DICT_EMPTY;
    return true;
}

def_dict_get_iter(dict_get_iter)
{
    iter->dict = dict;
    iter->pos = 0;
}

def_dict_iter_next(dict_iter_next)
{
    u32 i;
    while(1) {
        if (iter->pos >= iter->dict->cap)
            return false;
        
        i = dict_next_full_slot(iter->dict, iter->pos);
        if (i != Max_u32)
            break;
        
        iter->pos = dict_next_group(iter->pos);
    }
    iter->pos = i + 1;
    memcpy(ret, iter->dict->data + iter->dict->cap + stride * i + DICT_HASH_SIZE, stride - DICT_HASH_SIZE);
    return true;
}

def_destroy_dict(destroy_dict)
{
    deallocate(dict->alloc, dict->data);
    memset(dict, 0, sizeof(*dict));
}

//               ***************** EXTERNAL CODE *******************
//
// Code that is not mine, but which is very useful to me. I am very grateful
// to the creators, although I do intend to replace their implementations with
// my own at some point.
//

/*
 * rapidhash - Very fast, high quality, platform-independent hashing algorithm.
 * Copyright (C) 2024 Nicolas De Carli
 *
 * Based on 'wyhash', by Wang Yi <godspeed_china@yeah.net>
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - rapidhash source repository: https://github.com/Nicoshev/rapidhash
 */

#include <stdint.h>
#include <string.h>
#if defined(_MSC_VER)
#include <intrin.h>
#if defined(_M_X64) && !defined(_M_ARM64EC)
#pragma intrinsic(_umul128)
#endif
#endif

#ifdef __cplusplus
#define RAPIDHASH_NOEXCEPT noexcept
#define RAPIDHASH_CONSTEXPR constexpr
#ifndef RAPIDHASH_INLINE
#define RAPIDHASH_INLINE inline
#endif
#else
#define RAPIDHASH_NOEXCEPT
#define RAPIDHASH_CONSTEXPR static const
#ifndef RAPIDHASH_INLINE
#define RAPIDHASH_INLINE static inline
#endif
#endif

#ifndef RAPIDHASH_PROTECTED
#define RAPIDHASH_FAST
#elif defined(RAPIDHASH_FAST)
#error "cannot define RAPIDHASH_PROTECTED and RAPIDHASH_FAST simultaneously."
#endif

#ifndef RAPIDHASH_COMPACT
#define RAPIDHASH_UNROLLED
#elif defined(RAPIDHASH_UNROLLED)
#error "cannot define RAPIDHASH_COMPACT and RAPIDHASH_UNROLLED simultaneously."
#endif

#if defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
#define _likely_(x)  __builtin_expect(x,1)
#define _unlikely_(x)  __builtin_expect(x,0)
#else
#define _likely_(x) (x)
#define _unlikely_(x) (x)
#endif

#ifndef RAPIDHASH_LITTLE_ENDIAN
#if defined(_WIN32) || defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define RAPIDHASH_LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define RAPIDHASH_BIG_ENDIAN
#else
#warning "could not determine endianness! Falling back to little endian."
#define RAPIDHASH_LITTLE_ENDIAN
#endif
#endif

#define RAPID_SEED (0xbdd89aa982704029ull)

RAPIDHASH_CONSTEXPR uint64_t rapid_secret[3] = {0x2d358dccaa6c78a5ull, 0x8bb84b93962eacc9ull, 0x4b33a62ed433d4a3ull};

RAPIDHASH_INLINE void rapid_mum(uint64_t *A, uint64_t *B) RAPIDHASH_NOEXCEPT {
#if defined(__SIZEOF_INT128__)
    __uint128_t r=*A; r*=*B;
#ifdef RAPIDHASH_PROTECTED
    *A^=(uint64_t)r; *B^=(uint64_t)(r>>64);
#else
    *A=(uint64_t)r; *B=(uint64_t)(r>>64);
#endif
#elif defined(_MSC_VER) && (defined(_WIN64) || defined(_M_HYBRID_CHPE_ARM64))
#if defined(_M_X64)
#ifdef RAPIDHASH_PROTECTED
    uint64_t a, b;
    a=_umul128(*A,*B,&b);
    *A^=a;  *B^=b;
#else
    *A=_umul128(*A,*B,B);
#endif
#else
#ifdef RAPIDHASH_PROTECTED
    uint64_t a, b;
    b = __umulh(*A, *B);
    a = *A * *B;
    *A^=a;  *B^=b;
#else
    uint64_t c = __umulh(*A, *B);
    *A = *A * *B;
    *B = c;
#endif
#endif
#else
    uint64_t ha=*A>>32, hb=*B>>32, la=(uint32_t)*A, lb=(uint32_t)*B, hi, lo;
    uint64_t rh=ha*hb, rm0=ha*lb, rm1=hb*la, rl=la*lb, t=rl+(rm0<<32), c=t<rl;
    lo=t+(rm1<<32); c+=lo<t; hi=rh+(rm0>>32)+(rm1>>32)+c;
#ifdef RAPIDHASH_PROTECTED
    *A^=lo;  *B^=hi;
#else
    *A=lo;  *B=hi;
#endif
#endif
}

RAPIDHASH_INLINE uint64_t rapid_mix(uint64_t A, uint64_t B) RAPIDHASH_NOEXCEPT { rapid_mum(&A,&B); return A^B; }

#ifdef RAPIDHASH_LITTLE_ENDIAN
RAPIDHASH_INLINE uint64_t rapid_read64(const uint8_t *p) RAPIDHASH_NOEXCEPT { uint64_t v; memcpy(&v, p, sizeof(uint64_t)); return v;}
RAPIDHASH_INLINE uint64_t rapid_read32(const uint8_t *p) RAPIDHASH_NOEXCEPT { uint32_t v; memcpy(&v, p, sizeof(uint32_t)); return v;}
#elif defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
RAPIDHASH_INLINE uint64_t rapid_read64(const uint8_t *p) RAPIDHASH_NOEXCEPT { uint64_t v; memcpy(&v, p, sizeof(uint64_t)); return __builtin_bswap64(v);}
RAPIDHASH_INLINE uint64_t rapid_read32(const uint8_t *p) RAPIDHASH_NOEXCEPT { uint32_t v; memcpy(&v, p, sizeof(uint32_t)); return __builtin_bswap32(v);}
#elif defined(_MSC_VER)
RAPIDHASH_INLINE uint64_t rapid_read64(const uint8_t *p) RAPIDHASH_NOEXCEPT { uint64_t v; memcpy(&v, p, sizeof(uint64_t)); return _byteswap_uint64(v);}
RAPIDHASH_INLINE uint64_t rapid_read32(const uint8_t *p) RAPIDHASH_NOEXCEPT { uint32_t v; memcpy(&v, p, sizeof(uint32_t)); return _byteswap_ulong(v);}
#else
RAPIDHASH_INLINE uint64_t rapid_read64(const uint8_t *p) RAPIDHASH_NOEXCEPT {
    uint64_t v; memcpy(&v, p, 8);
    return (((v >> 56) & 0xff)| ((v >> 40) & 0xff00)| ((v >> 24) & 0xff0000)| ((v >>  8) & 0xff000000)| ((v <<  8) & 0xff00000000)| ((v << 24) & 0xff0000000000)| ((v << 40) & 0xff000000000000)| ((v << 56) & 0xff00000000000000));
}
RAPIDHASH_INLINE uint64_t rapid_read32(const uint8_t *p) RAPIDHASH_NOEXCEPT {
    uint32_t v; memcpy(&v, p, 4);
    return (((v >> 24) & 0xff)| ((v >>  8) & 0xff00)| ((v <<  8) & 0xff0000)| ((v << 24) & 0xff000000));
}
#endif

RAPIDHASH_INLINE uint64_t rapid_readSmall(const uint8_t *p, size_t k) RAPIDHASH_NOEXCEPT { return (((uint64_t)p[0])<<56)|(((uint64_t)p[k>>1])<<32)|p[k-1];}

RAPIDHASH_INLINE uint64_t rapidhash_internal(const void *key, size_t len, uint64_t seed, const uint64_t* secret) RAPIDHASH_NOEXCEPT {
    const uint8_t *p=(const uint8_t *)key; seed^=rapid_mix(seed^secret[0],secret[1])^len;  uint64_t  a,  b;
    if(_likely_(len<=16)){
        if(_likely_(len>=4)){
            const uint8_t * plast = p + len - 4;
            a = (rapid_read32(p) << 32) | rapid_read32(plast);
            const uint64_t delta = ((len&24)>>(len>>3));
            b = ((rapid_read32(p + delta) << 32) | rapid_read32(plast - delta)); }
        else if(_likely_(len>0)){ a=rapid_readSmall(p,len); b=0;}
        else a=b=0;
    }
    else{
        size_t i=len;
        if(_unlikely_(i>48)){
            uint64_t see1=seed, see2=seed;
#ifdef RAPIDHASH_UNROLLED
            while(_likely_(i>=96)){
                seed=rapid_mix(rapid_read64(p)^secret[0],rapid_read64(p+8)^seed);
                see1=rapid_mix(rapid_read64(p+16)^secret[1],rapid_read64(p+24)^see1);
                see2=rapid_mix(rapid_read64(p+32)^secret[2],rapid_read64(p+40)^see2);
                seed=rapid_mix(rapid_read64(p+48)^secret[0],rapid_read64(p+56)^seed);
                see1=rapid_mix(rapid_read64(p+64)^secret[1],rapid_read64(p+72)^see1);
                see2=rapid_mix(rapid_read64(p+80)^secret[2],rapid_read64(p+88)^see2);
                p+=96; i-=96;
            }
            if(_unlikely_(i>=48)){
                seed=rapid_mix(rapid_read64(p)^secret[0],rapid_read64(p+8)^seed);
                see1=rapid_mix(rapid_read64(p+16)^secret[1],rapid_read64(p+24)^see1);
                see2=rapid_mix(rapid_read64(p+32)^secret[2],rapid_read64(p+40)^see2);
                p+=48; i-=48;
            }
#else
            do {
                seed=rapid_mix(rapid_read64(p)^secret[0],rapid_read64(p+8)^seed);
                see1=rapid_mix(rapid_read64(p+16)^secret[1],rapid_read64(p+24)^see1);
                see2=rapid_mix(rapid_read64(p+32)^secret[2],rapid_read64(p+40)^see2);
                p+=48; i-=48;
            } while (_likely_(i>=48));
#endif
            seed^=see1^see2;
        }
        if(i>16){
            seed=rapid_mix(rapid_read64(p)^secret[2],rapid_read64(p+8)^seed^secret[1]);
            if(i>32)
                seed=rapid_mix(rapid_read64(p+16)^secret[2],rapid_read64(p+24)^seed);
        }
        a=rapid_read64(p+i-16);  b=rapid_read64(p+i-8);
    }
    a^=secret[1]; b^=seed;  rapid_mum(&a,&b);
    return  rapid_mix(a^secret[0]^len,b^secret[1]);
}

RAPIDHASH_INLINE uint64_t rapidhash_withSeed(const void *key, size_t len, uint64_t seed) RAPIDHASH_NOEXCEPT {
    return rapidhash_internal(key, len, seed, rapid_secret);
}

uint64_t rapidhash(void *key, size_t len) RAPIDHASH_NOEXCEPT {
    return rapidhash_withSeed(key, len, RAPID_SEED);
}

#endif // SOL_DEF
#endif // SOL_H
