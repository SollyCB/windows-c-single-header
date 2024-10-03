#define SOL_DEF
#include "sol.h"

struct thing {
    int x;
    struct list l;
};

int main() {
    
    struct list list;
    create_list(&list);
    
    struct thing a = {1};
    struct thing b = {2};
    struct thing c = {3};
    struct thing d = {4};
    
    list_add_tail(&list, &a.l);
    list_add_tail(&list, &b.l);
    list_add_tail(&list, &c.l);
    list_add_tail(&list, &d.l);
    
    struct thing *it;
    u32 count = 4;
    list_for(it, &list, l, count) {
        println("%i", it->x);
    }
    
    count = 4;
    list_for_rev(it, &list, l, count) {
        println("%i", it->x);
    }
    
    return 0;
}