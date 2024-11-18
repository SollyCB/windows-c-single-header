*Note that the name does not mean that it is Windows only, I just started programming it using Windows.
Eventually, I plan to remake this file from scratch when I feel that it too is too crufty and ugly. I already
have a strong desire to rewrite it using the coding style used in the [raddebugger](https://github.com/EpicGamesExt/raddebugger), because that repo is so beautiful.*

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
