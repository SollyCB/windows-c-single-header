#!/bin/bash

code="$PWD"
opts="-std=gnu99 -g -Wall -Wextra -Werror -Wno-unused-parameter -msse2 -DDEBUG -DSOL_DEF"
cd . > /dev/null
gcc $opts $code/main.c -o test
cd $code > /dev/null
