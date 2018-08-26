@ECHO OFF

:: The clean.cmd script cleans the build artifacts generated by build.cmd.

IF [%ROOTDIR%] EQU [] (
    CALL setenv.cmd
)
IF [%ROOTDIR%] EQU [] (
    ECHO ERROR: No ROOTDIR defined. Did setenv.cmd fail? Skipping clean.
    EXIT /B 1
)

SETLOCAL

IF EXIST "%DISTDIR%" (
    ECHO Removing directory "%DISTDIR%"...
    RMDIR /S /Q "%DISTDIR%"
)
IF EXIST "%OUTPUTDIR%" (
    ECHO Removing directory "%OUTPUTDIR%"...
    RMDIR /S /Q "%OUTPUTDIR%"
)

ENDLOCAL

EXIT /B 0

