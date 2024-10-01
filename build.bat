@echo off

set opts=-FC -GR- -EHa- -nologo -Zi -arch:AVX2
set code=%cd%
pushd .
cl %opts% %code%\main.c -Fetest
popd
