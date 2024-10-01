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

#define maxif(x) (0UL - (bool)(x))

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

// file.h
void write_stdout(char *buf, u64 size);

u64 write_file(char *uri, void *buf, u64 size);
u64 read_file(char *uri, void *buf, u64 size);

// print.h
int scb_snprintf(char *buf, int len, const char *fmt, ...);

#define print(fmt, ...) \
do { \
char m__buf[2046]; \
int m__len = scb_snprintf(m__buf, sizeof(m__buf), fmt, __VA_ARGS__); \
write_stdout(m__buf, m__len); \
} while(0);

#define println(fmt, ...) \
do { \
char m__buf[2046]; \
int m__len = scb_snprintf(m__buf, sizeof(m__buf), fmt, __VA_ARGS__); \
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

#define log_err(prec, ...) \
do { \
print("[%s, %s, %u%] ", __FILE__, __FUNCTION__, __LINE__); \
char m__buf[512]; \
print(__VA_ARGS__); \
fmt_error(m__buf, sizeof(m__buf), GetLastError()); \
println(" : %s", buf); \
log_break; \
} while(0);

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
        log_err("failed to open file %s", uri);
        goto out;
    }
    BOOL success = WriteFile(fd, buf, size, &res, NULL);
    if (!success) {
        log_err("failed to write file %s", uri);
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
        log_err("failed to open file %s", uri);
        goto out;
    }
    BOOL success = ReadFile(fd, buf, size, &res, NULL);
    if (!success) {
        log_err("failed to read file %s", uri);
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

static int pr_parse_u(char *buf, u64 x, int f)
{
    int bp = 0;
    int zc = 0;
    char tmp[128];
    
    if (f & PR_Z) {
        zc = clz64(x) & maxif(popcnt(x));
        if (f & PR_H)
            zc /= 4;
    }
    if (f & PR_H) {
        while(x > 0) {
            int b = x & 0xf;
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
    for(int i=0; i < bp; ++i)
        buf[i] = tmp[bp-1-i];
    return bp;
}

static int pr_parse_i(char *buf, s64 x, int f)
{
    int bp = 0;
    if (x < 0) {
        buf[bp++] = '-';
        x *= -1;
    }
    bp += pr_parse_u(buf + bp, x, f);
    return bp;
}

static int pr_parse_s(char *buf, char *x, int f)
{
    int bp = strlen(x);
    memcpy(buf, x, bp);
    return bp;
}

static int pr_parse_f(char *buf, double x, int f)
{
    // TODO(SollyCB): Idk if I will ever get round to implementing this myself...
    int bp = sprintf(buf, "%f", x);
    return bp;
}

static int pr_parse_c(char *buf, char x, int f)
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

int scb_snprintf(char *buf, int len, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    int f = 0;
    int bp = 0;
    int sl = strlen(fmt);
    
    for(int i=0; i < sl; ++i) {
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

#endif // SOL_DEF
#endif // SOL_H
