#if 0

#include <stdio.h>
#include <string.h>

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

#include <string.h>
#include <stdio.h>

// does not work with lvalues
#define typecheck(a, b, c) (b = (typeof(a))b, c)

// necessary for lvalue references
#define ptypecheck(a, b, c) (*b = *(typeof(a))b, c)

int fn_(void *a, void *b, long sz)
{
  memcpy(a, b, sz);
  return 0;
}

#define fn(a, b) fn_(ptypecheck(a, b, a), b, sizeof(*a))

struct one { int x; };
struct two { int x; };

#define TYPECHECK_PASSES 0

#if TYPECHECK_PASSES
int main(void) {
  struct one a = {5};
  struct one b = {10};

  printf("Before Copy: a = %i, b = %i\n", a.x, b.x);

  if (fn(&a, &b))
    return -1;

  printf("After Copy: a = %i, b = %i\n", a.x, b.x);

  return 0;
}
#else
int main(void) {
  struct one a = {5};
  struct two b = {10};

  printf("Before Copy: a = %i, b = %i", a.x, b.x);

  if (fn(&a, &b))
    return -1;

  printf("After Copy: a = %i, b = %i", a.x, b.x);

  return 0;
}
#endif

#define add(a, b) (ptypecheck(a, b), add_(a, b))

#define glue_(a, b) a##b
#define glue(a, b) glue_(a, b)
#define paste_(...) __VA_ARGS__
#define paste(...) paste_(__VA_ARGS__)
#define stringify_(...) #__VA_ARGS__
#define stringify(...) stringify_(__VA_ARGS__)

#define def_typed_dict(T, abbrev) typedef struct glue(abbrev, _dict) { T *dict; } glue(abbrev, _t);

def_typed_dict(struct one, one);

// int main(void) {
//   struct one a;
//   struct one b;
//   return fn(&a, &b);
// }
#else

#include "sol.h"
#include "names.h"

/*
 * Todo(scb):
 *   - array redo
 */

struct thing {
  u64 i;
  char *s;
  char c;
};

int main() {

  allocator_t alloc;
  create_allocator_arena(4096, &alloc);

  return 0;
}
#endif
