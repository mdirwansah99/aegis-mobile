@echo off
title Tolak AegisMobile Pro ke GitHub
color 0b
echo ========================================================
echo        AEGIS MOBILE PRO - DEPLOY KE GITHUB PAGES
echo ========================================================
echo.
echo Langkah ini akan memulakan git dalam folder ini dan
echo menolak fail ke akaun GitHub anda.
echo.

cd /d "%~dp0"

if not exist ".git" (
    echo [*] Memulakan repositori Git tempatan...
    git init
    git branch -M main
)

echo [*] Menambah semua fail AegisMobile...
git add .
git commit -m "Pelancaran AegisMobile Pro v2.0 dengan Signal Booster dan Anti-Scam"

echo.
echo ========================================================
echo Masukkan URL Repositori GitHub baharu anda.
echo Contoh: https://github.com/mdirwansah99/aegis-mobile.git
echo.
echo (Jika anda belum cipta repo di GitHub, sila buka
echo  https://github.com/new dan cipta repo bernama 'aegis-mobile')
echo ========================================================
echo.
set /p REPO_URL="Masukkan Git Repository URL (atau tekan ENTER jika guna mdirwansah99/aegis-mobile): "

if "%REPO_URL%"=="" (
    set REPO_URL=https://github.com/mdirwansah99/aegis-mobile.git
)

git remote remove origin 2>nul
git remote add origin %REPO_URL%

echo.
echo [*] Menolak kod ke %REPO_URL% di cawangan 'main'...
git push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================================
    echo [BERJAYA] Kod anda telah ditolak ke GitHub!
    echo.
    echo Langkah Terakhir (1 Minit Sahaja):
    echo 1. Buka repo anda di GitHub.
    echo 2. Pergi ke Settings -> Pages.
    echo 3. Di bawah 'Build and deployment' -> 'Branch':
    echo    Pilih 'main' dan folder '/ (root)', kemudian tekan SAVE.
    echo.
    echo Pautan telefon anda akan sedia di:
    echo https://mdirwansah99.github.io/aegis-mobile/
    echo ========================================================
) else (
    echo.
    echo [PERHATIAN] Sila pastikan anda telah mencipta repo tersebut di GitHub
    echo dan anda mempunyai kebenaran log masuk Git.
)

echo.
pause
