# STB Style Single Header General Library

I use as a drop in pseudo standard library, allowing for efficient and simple code reuse.

Usage is the same as the [stb libraries](https://github.com/nothings/stb): include the header to use the declarations, define SOL_DEF to expand the source.

## Example Usage

```C
// main.c

#define SOL_DEF
#include "sol.h"

int main() {

    char buf[256];
    scb_snprintf(buf, sizeof(buf), "Hello %s", "World");
    write_stdout(buf, strlen(buf));

    return 0;
}
```
