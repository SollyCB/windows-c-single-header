#define SOL_DEF
#include "sol.h"
#include "names.h"

struct thing {
    u64 i;
    char *s;
    char c;
};

def_typed_dict(thing, struct thing)

int main() {
    
    char buf[4];
    scb_snprintf(buf, (u32)sizeof(buf), "%s", "Hello");
    println("%s", buf);
    
    return 0;
}