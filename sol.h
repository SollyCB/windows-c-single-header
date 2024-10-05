#ifndef SOL_H
#define SOL_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <intrin.h>
#include <windows.h>

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

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
#define cl_array_len(x) (sizeof(x)/sizeof(x[0]))

#define memb_to_struct(memb, memb_of, memb_name) \
((typeof(memb_of))((u8*)memb - offsetof(typeof(*memb_of), memb_name)))

#define for_bits(pos, count, mask) \
for(count = 0, pos = (typeof(pos))ctz(mask); \
count < popcnt(mask); \
pos = (typeof(pos))ctz(mask & (0xffff << (pos + 1))), ++count)

enum type {
    TYPE_LINEAR,
    TYPE_ARENA,
};

// pp.h
#define pp_join(a, b) a ## b
#define pp_struct(name) struct name

// os.h
extern struct os {
    bool is_valid;
    u32 page_size;
    HANDLE stdout_handle;
} os;

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

// print.h
#define def_snprintf(name) u32 name(char *buf, u32 len, const char *fmt, ...)
def_snprintf(scb_snprintf);

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

// assert.h
#define assert(x) \
if (!(x)) { \
println("[%s, %s, %u] ASSERT : %s", __FILE__, __FUNCTION__, __LINE__, #x); \
__debugbreak(); \
}

#define log_break \
do { \
_mm_sfence(); \
__debugbreak(); \
} while(0);

#define log_error(...) \
do { \
print("[%s, %s, %u] LOG ERROR : ", __FILE__, __FUNCTION__, __LINE__); \
println(__VA_ARGS__); \
log_break; \
} while(0);

#define log_error_if(prec, ...) \
do { if (prec) log_error(__VA_ARGS__); } while(0);

#define log_os_error(...) \
do { \
char m__log_os_error_buf[512]; \
os_error_string(m__log_os_error_buf, sizeof(m__log_os_error_buf)); \
print("[%s, %s, %u] LOG OS ERROR : ", __FILE__, __FUNCTION__, __LINE__); \
print(__VA_ARGS__); \
println(" : %s", m__log_os_error_buf); \
log_break; \
} while(0);

#define log_os_error_if(prec, ...) \
do { if (prec) log_os_error(__VA_ARGS__); } while(0);

#define invalid_default_case log_error("invalid default case")

// math.h
static inline bool is_pow2(u64 x)
{
    // NOTE(SollyCB): I know that zero is not a power of two, but this function
    // acts on integers, so any code using it is doing so for alignment and offset purposes,
    // and zero being valid is therefore useful.
    return (x & (x - 1)) == 0;
}

static inline u64 mod_pow2(u64 l, u64 r)
{
    assert(is_pow2(r));
    return l & (r - 1);
}

static inline u64 next_pow2(u64 x) // TODO(SollyCB): There must be a better implementation...
{
    if (x == 0)
        return 1;
    return is_pow2(x) ? x : (u64)1 << clz(x);
}

static inline u64 align(u64 size, u64 alignment) {
    assert(is_pow2(alignment));
    u64 alignment_mask = alignment - 1;
    return (size + alignment_mask) & ~alignment_mask;
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

#define def_reallocate(name, type) void *name(type ## _t *alloc, void *old_p, u64 old_size, u64 new_size)
def_reallocate(linear_reallocate, linear);
def_reallocate(arena_reallocate, arena);

#define def_allocator_size(name, type) u64 name(type ## _t *alloc)
def_allocator_size(linear_size, linear);
def_allocator_size(arena_size, arena);

#define def_allocator_used(name, type) u64 name(type ## _t *alloc)
def_allocator_used(linear_used, linear);
def_allocator_used(arena_used, arena);

#define def_deallocate(name, type) void name(type ## _t *alloc, void *p, u64 size)
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

#define create_allocator_arena(buf, size, alloc) \
do { (alloc)->type = TYPE_ARENA; create_allocator(buf, size, alloc); } while(0);

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
        case TYPE_LINEAR: return linear_reallocate(&alloc->linear, old_p, old_size, new_size);
        case TYPE_ARENA: return arena_reallocate(&alloc->arena, old_p, old_size, new_size);
        default: invalid_default_case;
    }
    return NULL;
}

static inline def_deallocate(deallocate, allocator)
{
    switch(alloc->type) {
        case TYPE_LINEAR: linear_deallocate(&alloc->linear, p, size); break;
        case TYPE_ARENA: arena_deallocate(&alloc->arena, p, size); break;
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

// dict.h
typedef struct dict dict_t;
typedef struct dict_iter dict_iter_t;

#define def_create_dict(name) int name(u64 size, u64 stride, allocator_t *alloc, dict_t *dict)
#define def_dict_insert(name) void* dict_insert(dict_t *dict, struct string key, void *val, u64 stride)
#define def_dict_find(name) void* dict_find(dict_t *dict, struct string key, u64 stride)
#define def_dict_remove(name) bool dict_remove(dict_t *dict, struct string key, u64 stride)
#define def_dict_get_iter(name) void dict_get_iter(dict_t *dict, dict_iter_t *iter)
#define def_dict_iter_next(name) void* dict_iter_next(dict_iter_t *iter, u64 stride)
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
for(kv = func(dict_iter); kv; kv = func(dict_iter))

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
def_dict(abbrev ## _dict, pp_struct(abbrev ## _dict_kv)) \
def_dict_iter(abbrev ## _dict_iter, abbrev ## _dict_t) \
\
static inline void \
create_ ## abbrev ## _dict(u64 size, allocator_t *alloc, abbrev ## _dict_t *dict) \
{ \
create_dict(size, sizeof(*dict->data), alloc, (dict_t*)dict); \
} \
static inline struct abbrev ## _dict_kv* \
abbrev ## _dict_insert(abbrev ## _dict_t *dict, struct string key, typeof(value) *val) \
{ \
return (struct abbrev ## _dict_kv*)dict_insert((dict_t*)dict, key, val, sizeof(*dict->data)); \
} \
\
static inline struct abbrev ## _dict_kv* \
abbrev ## _dict_find(abbrev ## _dict_t *dict, struct string key) \
{ \
return (struct abbrev ## _dict_kv*)dict_find((dict_t*)dict, key, sizeof(*dict->data)); \
} \
\
static inline bool abbrev ## _dict_remove(abbrev ## _dict_t *dict, struct string key) \
{ \
return dict_remove((dict_t*)dict, key, sizeof(*dict->data)); \
} \
\
static inline void abbrev ## _dict_get_iter(abbrev ## _dict_t *dict, abbrev ## _dict_iter_t *iter) \
{ \
dict_get_iter((dict_t*)dict, (dict_iter_t*)iter); \
} \
\
static inline struct abbrev ## _dict_kv* \
abbrev ## _dict_iter_next(abbrev ## _dict_iter_t *iter) \
{ \
return (struct abbrev ## _dict_kv*)dict_iter_next((dict_iter_t*)iter, sizeof(*iter->dict->data)); \
} \
static inline void destroy_ ## abbrev ## _dict(abbrev ## _dict_t *dict) \
{ \
destroy_dict((dict_t*)dict, sizeof(*dict->data)); \
}

#ifdef SOL_DEF

// os.c
struct os os = {};

def_create_os(create_os)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    os.page_size = si.dwPageSize;
    os.stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
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

static u32 pr_parse_u(char *buf, u64 x, u32 f)
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
    for(u32 i=0; i < bp; ++i)
        buf[i] = tmp[bp-1-i];
    return bp;
}

static u32 pr_parse_i(char *buf, s64 x, u32 f)
{
    u32 bp = 0;
    if (x < 0) {
        buf[bp++] = '-';
        x *= -1;
    }
    bp += pr_parse_u(buf + bp, x, f);
    return bp;
}

static u32 pr_parse_s(char *buf, char *x, u32 f)
{
    u32 bp = (u32)strlen(x);
    memcpy(buf, x, bp);
    return bp;
}

static u32 pr_parse_f(char *buf, double x, u32 f)
{
    // TODO(SollyCB): Idk if I will ever get round to implementing this myself...
    u32 bp = sprintf(buf, "%f", x);
    return bp;
}

static u32 pr_parse_c(char *buf, char x, u32 f)
{
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
    
    for(u32 i=0; i < sl; ++i) {
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
            bp += pr_parse_i(buf + bp, x, f);
        } else if (f & PR_U) {
            u64 x = va_arg(va, u64);
            bp += pr_parse_u(buf + bp, x, f);
        } else if (f & PR_S) {
            char *x = va_arg(va, char*);
            bp += pr_parse_s(buf + bp, x, f);
        } else if (f & PR_F) {
            double x = va_arg(va, double);
            bp += pr_parse_f(buf + bp, x, f);
        } else if (f & PR_C) {
            char x = va_arg(va, char);
            bp += pr_parse_c(buf + bp, x, f);
        }
    }
    va_end(va);
    buf[bp++] = 0;
    return bp;
}

// alloc.c
struct arena_header {
    u64 validation_bits;
    linear_t linear;
    list_t list;
    rc_t rc;
};

#define ARENA_HEADER_SIZE align(sizeof(struct arena_header), 16)
#define ARENA_VALIDATION_BITS 0xcafebabecafebabe

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
    if (size < alloc->min_block_size)
        size = alloc->min_block_size;
    
    u8 *mem = os_allocate(size + ARENA_HEADER_SIZE);
    if (!mem)
        return NULL;
    
    struct arena_header *block = (struct arena_header*)(mem + size);
    memset(block, 0, sizeof(*block));
    
    block->validation_bits = ARENA_VALIDATION_BITS;
    create_linear(mem, size, &block->linear);
    alloc->block_count += 1;
    return block;
}

static void destroy_arena_block(arena_t *alloc, struct arena_header *block)
{
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
    rc_inc(&block->rc);
    return linear_allocate(&block->linear, size);
}

static void arena_header_deallocate(arena_t *alloc, struct arena_header *block, void *p, u64 size)
{
    log_error_if(!arena_header_is_valid(block), "Failed to validate arena header");
    if (!rc_dec(&block->rc)) {
        destroy_arena_block(alloc, block);
        return;
    }
    linear_deallocate(&block->linear, p, size);
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
    size = alloc_align(size);
    if (alloc->used + size > alloc->size)
        return NULL;
    
    alloc->used += size;
    return alloc->data + alloc->used - alloc_align(size);
}

def_reallocate(linear_reallocate, linear)
{
    if (linear_is_top(alloc, old_p, old_size)) {
        alloc->used -= alloc_align(old_size);
        alloc->used += alloc_align(new_size);
        return alloc->data + alloc->used - alloc_align(new_size);
    }
    if (new_size < old_size)
        return old_p;
    
    void *p = linear_allocate(alloc, new_size);
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
    if (linear_is_top(alloc, p, size))
        alloc->used -= alloc_align(size);
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
    void *p;
    struct arena_header *block = arena_find_block(alloc, old_p);
    
    if (linear_is_top(&block->linear, old_p, old_size)) {
        p = linear_reallocate(&block->linear, old_p, old_size, new_size);
        if (p)
            return p;
    }
    
    arena_header_deallocate(alloc, block, old_p, old_size);
    p = arena_allocate(alloc, new_size);
    memcpy(p, old_p, old_size);
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
    arena_header_deallocate(alloc, block, p, size);
}

def_destroy_allocator(destroy_arena, arena)
{
    struct arena_header *block, *tmp;
    list_for_safe(block, tmp, &alloc->block_list, list, alloc->block_count) {
        list_remove(&block->list);
        destroy_arena_block(alloc, block);
    }
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

#define dict_for_each_internal(dict_iter, kv, func, stride) \
for(kv = func(dict_iter, stride); kv; kv = func(dict_iter, stride))

#define dict_probe_loop(idx, probe) \
for(idx = dict_probe_next(probe); idx != Max_u32; idx = dict_probe_next(probe))

#define def_dict_insert_hash(name) static void* name(dict_t *dict, u64 key, void *val, u64 stride)
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

static int dict_copy(dict_t *new_dict, dict_t *old_dict, u64 stride)
{
    dict_iter_t it;
    dict_get_iter(old_dict, &it);
    
    struct dict_kv *kv;
    dict_for_each_internal(&it, kv, dict_iter_next, stride) {
        if (!dict_insert_hash(new_dict, kv->key, &kv->val, stride))
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
            return NULL;
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
            memcpy(v, val, stride - 8);
            
            dict->rem -= 1;
            return kv;
        }
    }
    log_error("Failed to find empty slot");
    return NULL;
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
    return i == Max_u32 ? NULL : dict->data + dict->cap + stride * i;
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
            return NULL;
        
        i = dict_next_full_slot(iter->dict, iter->pos);
        if (i != Max_u32)
            break;
        
        iter->pos = dict_next_group(iter->pos);
    }
    iter->pos = i + 1;
    return iter->dict->data + iter->dict->cap + stride * i;
}

def_destroy_dict(destroy_dict)
{
    deallocate(dict->alloc, dict->data, dict->cap + dict->cap * stride);
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