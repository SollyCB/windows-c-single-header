#!/bin/bash

code="$PWD"
opts="-g -Wall -Wextra -Werror -msse2 -DSOL_DEF"
cd . > /dev/null
gcc $opts $code/main.c -o test
cd $code > /dev/null
