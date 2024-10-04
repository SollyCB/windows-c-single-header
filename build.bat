@echo off

set opts=-FC -GR- -EHa- -nologo -Zi -W4 -WX -wd4201 -wd4100
set code=%cd%
pushd .
cl %opts% %code%\main.c -Fetest
popd
