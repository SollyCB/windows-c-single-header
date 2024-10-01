#!/bin/bash

code="$PWD"
opts=-g
cd . > /dev/null
g++ $opts $code/main.c -o test
cd $code > /dev/null
