@echo off
title NOTE CRYPT - Auto Deploy GitHub + Vercel
color 0C

echo ========================================
echo    NOTE CRYPT - Auto Deploy
echo    GitHub + Vercel
echo ========================================
echo.

cd /d D:\note-crypt-web

echo [1/5] Checking git status...
git status
echo.

echo [2/5] Adding all changes...
git add .
echo.

echo [3/5] Committing changes...
set /p commit_msg="Enter commit message (default: update): "
if "%commit_msg%"=="" set commit_msg=update
git commit -m "%commit_msg%"
echo.

echo [4/5] Pushing to GitHub...
git push origin main
echo.

echo [5/5] Deploying to Vercel...
vercel --prod
echo.

echo ========================================
echo    DEPLOY COMPLETE!
echo    GitHub: https://github.com/phaqxychicz/note-crypt-web
echo    Vercel: https://note-crypt-web.vercel.app
echo ========================================
echo.
pause