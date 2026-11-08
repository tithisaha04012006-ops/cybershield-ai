@echo off
setlocal enabledelayedexpansion
title Deploy CyberShield AI to GitHub and Render

echo ========================================================
echo   CyberShield AI - Automated GitHub & Render Deployer
echo   HackMatrix '26 Project
echo ========================================================
echo.

if "%~1"=="" (
    set /p GITHUB_USER="Enter your GitHub username (e.g. tithisaha): "
) else (
    set GITHUB_USER=%~1
)

if "%GITHUB_USER%"=="" (
    echo [ERROR] GitHub username cannot be empty.
    pause
    exit /b 1
)

echo.
echo [1/3] Configuring Git remote origin for https://github.com/%GITHUB_USER%/cybershield-ai.git ...
git remote remove origin 2>nul
git remote add origin https://github.com/%GITHUB_USER%/cybershield-ai.git

echo.
echo [2/3] Pushing to GitHub (main branch)...
echo (If a GitHub sign-in window appears, please authorize Git Credential Manager)
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo [SUCCESS] Code successfully pushed to GitHub!
    echo Repository: https://github.com/%GITHUB_USER%/cybershield-ai
    echo ========================================================
    echo.
    echo [3/3] Opening Render to deploy your live Web Service...
    start https://dashboard.render.com/select-repo?type=web
    echo.
    echo In Render:
    echo 1. Select 'cybershield-ai'
    echo 2. Click 'Create Web Service'
    echo 3. Copy your live HTTPS link (e.g. https://cybershield-ai.onrender.com)
    echo    and share it with your 4 hackathon teammates!
) else (
    echo.
    echo [NOTE] Push failed. Have you created the empty repository on GitHub first?
    echo If not, please open https://github.com/new and create a repository named:
    echo cybershield-ai
    echo Then run this script again!
    start https://github.com/new
)

echo.
pause
