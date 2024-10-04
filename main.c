#define SOL_DEF
#include "sol.h"

struct thing {
    int x;
    struct list l;
};

int main() {
    
    char *str = "Hello There!";
    write_file("file.txt", str, strlen(str));
    
    u64 size = read_file("file.txt", NULL, 0);
    char *buf = malloc(size + 1);
    read_file("file.txt", buf, size);
    buf[size] = 0;
    println("size %u, buf %s", size, buf);
    
    return 0;
}