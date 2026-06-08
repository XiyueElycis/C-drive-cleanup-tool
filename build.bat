@echo off
chcp 65001 >nul
title 构建 DiskCleaner 独立运行包

echo ============================================
echo   DiskCleaner - PyInstaller 打包构建
echo ============================================
echo.

echo [1/2] 清理旧的构建文件...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "*.spec" del /f /q "*.spec"
echo        完成

echo.
echo [2/2] 开始 PyInstaller 打包...
echo        这可能需要几分钟，请耐心等待...
echo.

pyinstaller ^
    --name="C盘深度清理工具" ^
    --onedir ^
    --console ^
    --add-data="templates;templates" ^
    --add-data="static;static" ^
    --hidden-import=flask ^
    --hidden-import=send2trash ^
    --hidden-import=jinja2 ^
    --hidden-import=jinja2.ext ^
    --hidden-import=werkzeug ^
    --exclude-module=matplotlib ^
    --exclude-module=numpy ^
    --exclude-module=pandas ^
    --exclude-module=PIL ^
    --exclude-module=cv2 ^
    --exclude-module=scipy ^
    --clean ^
    --noconfirm ^
    app.py

echo.
echo ============================================
echo   构建完成！
echo   输出目录: dist\C盘深度清理工具\
echo ============================================
echo.

REM 复制 README 到输出目录
copy "README.md" "dist\C盘深度清理工具\README.md" >nul
echo 已复制 README.md 到输出目录

pause
