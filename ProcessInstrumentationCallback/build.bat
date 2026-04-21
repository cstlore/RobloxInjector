@echo off
REM ProcessInstrumentationCallback Build Script
REM Compile MASM x64 stub and link with C++ implementation

setlocal enabledelayedexpansion

echo Building ProcessInstrumentationCallback
echo ========================================

REM Configuration
set ASM_SOURCE=ProcessInstrumentationStub.asm
set CPP_SOURCES=ProcessInstrumentation.cpp main.cpp
set OBJ_DIR=obj
set OUTPUT=ProcessInstrumentation.exe

REM Create output directory
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

REM Step 1: Assemble MASM x64 stub
echo [1/3] Assembling MASM x64 stub...
ml64 ^
    /c ^
    /Fo%OBJ_DIR%\%ASM_SOURCE:.asm=% ^
    /Fa ^
    /Zi ^
    /arch:AVX ^
    %ASM_SOURCE%

if errorlevel 1 (
    echo [!] Assembly failed
    exit /b 1
)
echo [+] Assembly complete: %OBJ_DIR%\%~n1 ASM_SOURCE%.obj

REM Step 2: Compile C++ sources
echo [2/3] Compiling C++ sources...
cl ^
    /c ^
    /EHsc ^
    /O2 ^
    /Zi ^
    /MD ^
    /std:c++17 ^
    /I. ^
    /Fe%OBJ_DIR%\ProcessInstrumentation.obj ^
    %CPP_SOURCES%

if errorlevel 1 (
    echo [!] Compilation failed
    exit /b 1
)
echo [+] Compilation complete

REM Step 3: Link objects
echo [3/3] Linking executable...
link ^
    /NOLOGO ^
    /OUT:%OUTPUT% ^
    /SUBSYSTEM:CONSOLE ^
    /DEBUG ^
    /OPT:REF ^
    /OPT:ICF ^
    %OBJ_DIR%\ProcessInstrumentationStub.obj ^
    %OBJ_DIR%\ProcessInstrumentation.obj ^
    %OBJ_DIR%\main.obj ^
    ntdll.lib ^
    kernel32.lib

if errorlevel 1 (
    echo [!] Linking failed
    exit /b 1
)

echo ========================================
echo [+] Build successful: %OUTPUT%
echo ========================================

endlocal
