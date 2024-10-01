#define SOL_DEF
#include "sol.h"

int main() {
    println("The number is %ub \nor %uh \nor %uzb \nor %uzh", (u64)13, (u64)13, (u64)13, (u64)13);
    return 0;
}