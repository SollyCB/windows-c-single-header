#if 1

struct thing {
  int x;
};

struct thing x,y;

int add_(void *x, void *y)
{
  int *a = x;
  int *b = y;
  return *a + *b;
}

#define typecheck(a, b) \
    do { \
        typeof(a) m__typecheck = b; \
        m__typecheck = m__typecheck; \
    } while(0)

#define add(a, b) \
  do { \
    typecheck(a, b); \
    add_(a, b); \
  } while(0)

struct one { int x; };
struct two { int x; };

#define glue_(a, b) a##b
#define glue(a, b) glue_(a, b)
#define paste_(...) __VA_ARGS__
#define paste(...) paste_(__VA_ARGS__)
#define stringify_(...) #__VA_ARGS__
#define stringify(...) stringify_(__VA_ARGS__)

#define def_typed_dict(T, abbrev) typedef struct glue(abbrev, _dict) { T *dict; } glue(abbrev, _t);

def_typed_dict(struct one, one)

int main(void) {

  printf("%lu\n", sizeof((struct {int x;}));

  return 0;
}
#else
#include "sol.h"

struct thing {
  u64 i;
  char *s;
  char c;
};

def_typed_array(thing, struct thing);

int main() {

  allocator_t alloc;
  create_allocator_arena(4096, &alloc);

  struct thing t;
  t.i = 20;

  return 0;
}
#endif
