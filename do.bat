@echo off
REM make -fMakefile -DDEBUG
make -fMakefile
del *.obj
del *.res
pause
upx --best --crp-ms=999999 --nrv2b inPEct.exe
pause
