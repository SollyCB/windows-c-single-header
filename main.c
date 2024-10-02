#define SOL_DEF
#include "sol.h"

struct thing {
    int x;
    struct list l;
};

int main() {
    
    struct list list;
    init_list(&list);
    
    struct thing a = {1};
    struct thing b = {2};
    struct thing c = {3};
    struct thing d = {4};
    
    list_add_tail(&list, &a.l);
    list_add_tail(&list, &b.l);
    list_add_tail(&list, &c.l);
    list_add_tail(&list, &d.l);
    
    struct thing *it;
    list_for_each(it, &list, l) {
        println("%i", it->x);
    }
    
    list_for_each_rev(it, &list, l) {
        println("%i", it->x);
    }
    
    struct thing *tmp;
    
#if 1
    list_for_each_rev_safe(it, tmp, &list, l) {
        println("%u", it->x);
        list_remove(&it->l);
    }
#else
    list_for_each(it, &list, l) {
        println("%u", it->x);
        list_remove(&it->l);
    }
#endif
    
    return 0;
}