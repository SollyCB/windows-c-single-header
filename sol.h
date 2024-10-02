#ifndef SOL_H
#define SOL_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <intrin.h>
#include <ammintrin.h>
#include <immintrin.h>
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

#define memb_to_struct(memb, memb_of, memb_name) \
((typeof(memb_of))((u8*)memb - offsetof(typeof(*memb_of), memb_name)))

#define fmt_error(buf, size, err) \
do { \
FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, 0, 0, buf, size, NULL); \
} while (0);

#define print_error() \
do { \
char m__buf[512]; \
fmt_error(m__buf, sizeof(m__buf), GetLastError()); \
printf("%s\n", m__buf); \
} while(0);

enum type {
    TYPE_LINEAR,
    TYPE_ARENA,
};

static inline uint64 align(uint64 size, uint64 alignment) {
    const uint64 alignment_mask = alignment - 1;
    return (size + alignment_mask) & ~alignment_mask;
}

// file.h
void write_stdout(char *buf, u64 size);

u64 write_file(char *uri, void *buf, u64 size);
u64 read_file(char *uri, void *buf, u64 size);

// print.h
u32 scb_snprintf(char *buf, u32 len, const char *fmt, ...);

#define print(fmt, ...) \
do { \
char m__buf[2046]; \
u32 m__len = scb_snprintf(m__buf, sizeof(m__buf), fmt, __VA_ARGS__); \
write_stdout(m__buf, m__len); \
} while(0);

#define println(fmt, ...) \
do { \
char m__buf[2046]; \
u32 m__len = scb_snprintf(m__buf, sizeof(m__buf), fmt, __VA_ARGS__); \
m__buf[m__len++] = '\n'; \
write_stdout(m__buf, m__len); \
} while(0);

// assert.h
#define assert(x) \
if (!(x)) { \
println("%s", #x); \
__debugbreak(); \
}

#define log_break \
do { \
_mm_sfence(); \
__debugbreak(); \
} while(0);

#define log_if(prec, ...) \
do { \
if ((prec)) { \
print("[%s, %s, %u%] %s : ", __FILE__, __FUNCTION__, __LINE__, #prec); \
println(__VA_ARGS__); \
log_break; \
} \
} while(0);

#define log_error(...) \
do { \
print("[%s, %s, %u%] %s : ERROR ", __FILE__, __FUNCTION__, __LINE__); \
println(__VA_ARGS__); \
log_break; \
} while(0);

#define log_system_error(...) \
do { \
print("[%s, %s, %u%] ", __FILE__, __FUNCTION__, __LINE__); \
char m__buf[512]; \
print(__VA_ARGS__); \
fmt_error(m__buf, sizeof(m__buf), GetLastError()); \
println(" : %s", buf); \
log_break; \
} while(0);

#define invalid_default_case log_error("invalid default case")

// list.h
struct list {
    struct list *next;
    struct list *prev;
};

static inline void init_list(struct list *list)
{
    list->next = list;
    list->prev = list;
}

static inline bool list_is_empty(struct list *list)
{
    return list->next == NULL;
}

static inline void list_add_head(struct list *list, struct list *new_memb)
{
    struct list *next = list->next;
    next->prev = new_memb;
    list->next = new_memb;
    new_memb->prev = list;
    new_memb->next = next;
    if (list->prev == list)
        list->prev = new_memb;
}

static inline void list_add_tail(struct list *list, struct list *new_memb)
{
    struct list *prev = list->prev;
    prev->next = new_memb;
    list->prev = new_memb;
    new_memb->next = list;
    new_memb->prev = prev;
    if (list->next == list)
        list->next = new_memb;
}

static inline bool list_remove(struct list *list)
{
    if (list->next == list->prev)
        return false;
    
    struct list *next = list->next;
    struct list *prev = list->prev;
    next->prev = prev;
    prev->next = next;
    
    return true;
}

#define list_for_each(it, head, memb_name) \
for(it = memb_to_struct((head)->next, it, memb_name); \
&it->memb_name != head; \
it = memb_to_struct(it->memb_name.next, it, memb_name))

#define list_for_each_rev(it, head, memb_name) \
for(it = memb_to_struct((head)->prev, it, memb_name); \
&it->memb_name != head; \
it = memb_to_struct(it->memb_name.prev, it, memb_name))

#define list_for_each_safe(it, tmp, head, memb_name) \
for(it = memb_to_struct((head)->next, it, memb_name), tmp = it; \
it = tmp, &it->memb_name != head; \
it = memb_to_struct(it->memb_name.next, it, memb_name), tmp = it)

#define list_for_each_rev_safe(it, tmp, head, memb_name) \
for(it = memb_to_struct((head)->prev, it, memb_name), tmp = it; \
it = tmp, &it->memb_name != head; \
it = memb_to_struct(it->memb_name.prev, it, memb_name), tmp = it)

// alloc.h
typedef struct allocator allocator_t;
typedef struct arena arena_t;
typedef struct linear linear_t;

#define def_allocate_fn(name) void *name(allocator_t *alloc, u64 size)
#define def_reallocate_fn(name) void *name(allocator_t *alloc, void *p, u64 old_size, u64 new_size)
#define def_deallocate_fn(name) void name(allocator_t *alloc, void *p)

struct linear {
    u64 cap;
    u64 used;
    u8 *data;
};

struct arena_block {
    struct linear linear;
    struct list list;
};

struct arena {
    u32 block_count;
    u32 min_block_size;
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

def_allocate_fn(allocate_linear);
def_reallocate_fn(reallocate_linear);
def_deallocate_fn(deallocate_linear);

def_allocate_fn(allocate_arena);
def_reallocate_fn(reallocate_arena);
def_deallocate_fn(deallocate_arena);

def_allocate_fn(allocate) {
    switch(alloc->type) {
        case TYPE_LINEAR: return allocate_linear(alloc, size);
        case TYPE_ARENA: return allocate_arena(alloc, size);
        default:
        invalid_default_case;
    }
    return NULL;
}

def_reallocate_fn(reallocate) {
    switch(alloc->type) {
        case TYPE_LINEAR: return reallocate_linear(alloc, p, old_size, new_size);
        case TYPE_ARENA: return reallocate_arena(alloc, p, old_size, new_size);
        default:
        invalid_default_case;
    }
    return NULL;
}

def_deallocate_fn(deallocate) {
    switch(alloc->type) {
        case TYPE_LINEAR: deallocate_linear(alloc, p);
        case TYPE_ARENA: deallocate_arena(alloc, p);
        default:
        invalid_default_case;
    }
}

#ifdef SOL_DEF

// file.c
enum {
    FILE_READ = 0x0,
    FILE_WRITE = 0x01,
    FILE_CREATE = 0x02,
};

void write_stdout(char *buf, u64 size)
{
    HANDLE fd = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(fd, buf, size, NULL, NULL);
}

u64 write_file(char *uri, void *buf, u64 size)
{
    u32 res = 0;
    HANDLE fd = CreateFile(uri, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd != INVALID_HANDLE_VALUE) {
        log_system_error("failed to open file %s", uri);
        goto out;
    }
    BOOL success = WriteFile(fd, buf, size, &res, NULL);
    if (!success) {
        log_system_error("failed to write file %s", uri);
        goto out;
    }
    out:
    CloseHandle(fd);
    return res;
}

u64 read_file(char *uri, void *buf, u64 size)
{
    u32 res = 0;
    HANDLE fd = CreateFile(uri, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd != INVALID_HANDLE_VALUE) {
        log_system_error("failed to open file %s", uri);
        goto out;
    }
    BOOL success = ReadFile(fd, buf, size, &res, NULL);
    if (!success) {
        log_system_error("failed to read file %s", uri);
        goto out;
    }
    out:
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
    
    if (f & PR_Z) {
        zc = clz64(x) & maxif(popcnt(x));
        if (f & PR_H)
            zc /= 4;
    }
    if (f & PR_H) {
        while(x > 0) {
            u32 b = x & 0xf;
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
    u32 bp = strlen(x);
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

u32 scb_snprintf(char *buf, u32 len, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    u32 f = 0;
    u32 bp = 0;
    u32 sl = strlen(fmt);
    
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
def_allocate_fn(allocate_linear)
{
    size = alloc_align(size);
    if (alloc->linear.used + size > alloc->linear.cap)
        return NULL;
    
    alloc->linear.used += size;
    return alloc->linear.data + alloc->linear.used - alloc_align(size);
}

def_reallocate_fn(reallocate_linear)
{
    if (p == alloc->linear.data + alloc->linear.used - alloc_align(old_size)) {
        alloc->linear.used -= alloc_align(old_size);
        alloc->linear.used += alloc_align(new_size);
        return alloc->linear.data + alloc->linear.used - alloc_align(new_size);
    }
    
    if (new_size < old_size)
        return p;
    
    void *ret = allocate_linear(alloc, new_size);
    memcpy(ret, p, old_size);
    return ret;
}

def_deallocate_fn(deallocate_linear) {}

def_allocate_fn(allocate_arena)
{
}

def_reallocate_fn(reallocate_arena)
{
}

def_deallocate_fn(deallocate_arena)
{
}

#endif // SOL_DEF
#endif // SOL_H
