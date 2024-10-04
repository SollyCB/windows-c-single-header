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

enum type {
    TYPE_LINEAR,
    TYPE_ARENA,
};

static inline u64 align(u64 size, u64 alignment) {
    const u64 alignment_mask = alignment - 1;
    return (size + alignment_mask) & ~alignment_mask;
}

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

#define def_create_allocator(name, type) void name(void *buf, u64 size, type ## _t *alloc)
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
        case TYPE_LINEAR: create_linear(buf, size, &alloc->linear); break;
        case TYPE_ARENA: create_arena(buf, size, &alloc->arena); break;
        default: invalid_default_case;
    }
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
    if (fd != INVALID_HANDLE_VALUE) {
        log_os_error("failed to open file %s", uri);
        goto out;
    }
    BOOL success = WriteFile(fd, buf, (u32)size, (LPDWORD)&res, NULL);
    if (!success) {
        log_os_error("failed to write file %s", uri);
        goto out;
    }
    out:
    CloseHandle(fd);
    return res;
}

def_read_file(read_file)
{
    OFSTRUCT info;
    if (!buf) {
        HFILE fd = OpenFile(uri, &info, OF_PARSE);
        if (fd == HFILE_ERROR) {
            println("INVALID");
        } else {
            println("CLOSE IT");
        }
    }
    u32 res = 0;
    HANDLE fd = CreateFile(uri, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        log_os_error("Failed to open file %s", uri);
        goto out;
    }
    BOOL success = ReadFile(fd, buf, (u32)size, (LPDWORD)&res, NULL);
    if (!success) {
        log_os_error("Failed to read file %s", uri);
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
        if ((u8*)p > block->linear.data &&
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
    
    if (!buf)
        buf = os_allocate(size);
    
    alloc->data = buf;
    alloc->size = size;
    alloc->used = 0;
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

#endif // SOL_DEF
#endif // SOL_H