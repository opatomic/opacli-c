@echo off
setlocal EnableDelayedExpansion

:: note: if file names contain non-ascii characters then user should run `chcp 65001`

:: determine whether script was run by double clicking in explorer
echo %cmdcmdline% | findstr /i /c:"%~nx0" >NUL 2>&1 && set standalone=1

:: note: to find visual studio path, should use vswhere.exe but it wasn't working on my Win10 laptop; it returns nothing.
:: vswhere is always located at: "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
:: command should be something like:
::    "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -legacy -latest -property installationPath

:: note: %VCInstallDir% is set when vcvarsall.bat (or equivalent) has been run and environment is initialized
if "%VCInstallDir%"=="" (
	echo VC vars not set. Attempting to locate and run vcvarsall.bat %PROCESSOR_ARCHITECTURE%

	vswhere -legacy -latest -property installationPath >nul 2>&1 && (
		for /F "tokens=* USEBACKQ" %%i IN (`vswhere -legacy -latest -property installationPath`) do (set VSWHERERES=%%i)
	) || (
		echo vswhere.exe cannot be used to locate vcvarsall.bat
	)

	if not "!VSWHERERES!"=="" (
		echo Attempting to init using vswhere.exe result "!VSWHERERES!"
		call :InitMSVC "!VSWHERERES!\VC\Auxiliary\Build\vcvarsall.bat"
	)

	:: TODO: add more paths to check
	call :InitMSVC "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
	call :InitMSVC "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
	call :InitMSVC "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
	call :InitMSVC "%ProgramFiles(x86)%\Microsoft Visual Studio\2018\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
	call :InitMSVC "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
)
if "%VCInstallDir%"=="" (
	echo error: could not init MSVC environment
	if defined standalone pause
	exit /b 1
)


set ERRCODE=0
set SRCDIR=%cd%\..\src
set TMPDIR=%cd%\tmp
set OUTDIR=%cd%\out
set DEPDIR=%cd%\dep
set UTILDIR=%cd%\util
set LIBTOMDIR=%cd%\..\deps\libtommath
set PBFN=%TMPDIR%\parallel.txt



set MSVCOPTS=-Ox -Z7 /MD

:: C4204: initialize a struct or array with a non-constant value
:: C4710: a function was not inlined
:: C4820: indicates areas of unused struct space (padding added to fill gaps for proper alignment)
:: C5045: indicates areas of code possibly affected by spectre vuln
set MSVCWARN=-Wall -wd4204 -wd4710 -wd4820 -wd5045

:: -Wall includes some really useless warnings; use -W4 instead
:: C4127: conditional expression is constant
:: C4204: initialize a struct or array with a non-constant value
:: TODO: determine if there's any additional warnings to include/exclude
set MSVCWARN=-W4 -wd4127 -wd4204



if exist "%TMPDIR%" rmdir /S /Q "%TMPDIR%"
if not exist "%TMPDIR%" mkdir "%TMPDIR%"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
if not exist "%TMPDIR%" mkdir "%TMPDIR%"
if exist "%OUTDIR%\opacli.exe" del "%OUTDIR%\opacli.exe"


if not "%PBFN%"=="" (
	if not exist "%UTILDIR%" mkdir "%UTILDIR%"
	if exist "%UTILDIR%\parallel.exe" del "%UTILDIR%\parallel.exe"
	if exist "%UTILDIR%\parallel.obj" del "%UTILDIR%\parallel.obj"
	if exist "%PBFN%" del "%PBFN%"
	cl -nologo -Ox -Z7 /MD -W4 "-Fo%UTILDIR%\parallel.obj" parallel.c /link "/out:%UTILDIR%\parallel.exe" /debug:none
	if exist "%UTILDIR%\parallel.obj" del "%UTILDIR%\parallel.obj"
)

set INCS="-I."
mkdir "%TMPDIR%\libtommath"
call :BuildDir "%LIBTOMDIR%\*.c" "%TMPDIR%\libtommath"

call :pbuild

pushd "%TMPDIR%\libtommath"
call :GetFLIST .\*.obj
lib -nologo "-out:..\tommath.lib" %FLIST%
popd
rmdir /S /Q "%TMPDIR%\libtommath"

::mkdir %TMPDIR%\libtommath
::xcopy %LIBTOMDIR% %TMPDIR%\libtommath /e
::pushd %TMPDIR%\libtommath
::nmake -f makefile.msvc clean
::nmake -f makefile.msvc default "CFLAGS=%MSVCOPTS%"
::cp tommath.lib ..
::popd
::rmdir /S /Q %TMPDIR%\libtommath


set OPAC_VERSION=0.1.58
set /p OPACLIVER=<version.txt
:: TODO: if git is installed, and this directory is a proper git repo, determine whether the source
::   is modified and if not then assign a proper version string (without -win or -dev appended)
set OPACLIVER=%OPACLIVER%-win-dev
:: note: if compiling with threads support: add -D_AMD64_ to allow including synchapi.h rather than windows.h in opamutex.h
set DEFS=-DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0500 -DWINVER=0x0500 -DOPA_NOTHREADS -DOPAC_VERSION=\"%OPAC_VERSION%\" -DOPACLI_VERSION=\"%OPACLIVER%\" -DOPABIGINT_USE_LTM
set INCS="-I%LIBTOMDIR%"

call :GitCloneTag https://github.com/opatomic/opac-c.git "%DEPDIR%\opac-c" "v%OPAC_VERSION%"
if not %ERRCODE%==0 (
	if defined standalone pause
	exit /b %ERRCODE%
)
call :BuildDir "%DEPDIR%\opac-c\src\*.c" "%TMPDIR%"
set INCS=%INCS% "-I%DEPDIR%\opac-c\src"
set INCS=%INCS% "-I%SRCDIR%"
call :BuildDir ..\src\*.c "%TMPDIR%"
call :BuildDir ..\src\opatls\*.c "%TMPDIR%"

call :pbuild

:: TODO: determine how to link with msvcrt.dll rather than visual c runtime
::  use dumpbin.exe + script-to-modify-output + lib.exe
::  https://gist.github.com/SolomonSklash/fc02b48a7a70ecb1508977a8e41d43e5

call :GetFLIST "%TMPDIR%\*.obj"
cl -nologo /MD "-Fe%OUTDIR%\opacli.exe" %FLIST% "%TMPDIR%\tommath.lib" ws2_32.lib advapi32.lib

::set LNOPTS=/MANIFEST:NO /OPT:REF /OPT:NOICF /DEBUG /nodefaultlib:libcmt.lib
::link -nologo %LNOPTS% "/out:%OUTDIR%\opacli.exe" %FLIST% "%LIBTOMDIR%\tommath.lib" ws2_32.lib msvcrt.lib kernel32.lib

echo done.
if exist "%OUTDIR%\opacli.exe" (
	echo opacli.exe is in out directory
	set ERRCODE=0
) else (
	echo build failed
	set ERRCODE=1
)
if defined standalone pause
exit /b %ERRCODE%



:GitCloneTag (
	if not exist %2\ (
		git clone %1 %2
	)
	pushd %2
	:: TODO: only fetch/checkout if needed
	git fetch
	git checkout tags/%3
	for /F "tokens=* USEBACKQ" %%i in (`git status --porcelain`) do (set GITSTATUS=%%i)
	if not "%GITSTATUS%"=="" (
		echo error: There are changes to %2 project. Must revert or check in changes.
		set ERRCODE=1
	)
	popd
	goto :EOF
)

:InitMSVC (
	if "%VCInstallDir%"=="" (
		if exist %1 (
			call %1 %PROCESSOR_ARCHITECTURE%
		) else (
			echo %1 does not exist
		)
	)
	goto :EOF
)

:GetFLIST (
	SET FLIST=
	for %%i in (%1) do (
		:: note: when appending to end of variable, must use: setlocal EnableDelayedExpansion
		SET FLIST=!FLIST! "%%i"
	)
	goto :EOF
)

:BuildFile (
	if "%PBFN%"=="" (
		echo building %~nx1
		:: note: changing current directory so that __FILE__ is a string with only the file's basename (no extra directory info)
		pushd %~dp1
		cl -nologo -c %MSVCOPTS% %MSVCWARN% %DEFS% %INCS% "-Fo%~2\%~n1.obj" "%~nx1"
		popd
	) else (
		echo %~dp1 >> "%PBFN%"
		echo cl -nologo -c %MSVCOPTS% %MSVCWARN% %DEFS% %INCS% "-Fo%~2\%~n1.obj" "%~nx1" >> "%PBFN%"
		echo.>>"%PBFN%"
	)
	goto :EOF
)

:BuildDir (
	for %%i in (%1) do (
		call :BuildFile "%%i" %2
	)
	goto :EOF
)

:pbuild (
	if not "%PBFN%"=="" (
		"%UTILDIR%\parallel" < "%PBFN%"
		del "%PBFN%"
	)
	goto :EOF
)

:EOF

