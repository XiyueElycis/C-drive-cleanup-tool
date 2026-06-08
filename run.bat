@echo off
chcp 65001 >nul
title C盘深度清理工具 (开发模式)

echo ============================================
echo   C盘深度清理工具 v1.0 (开发模式)
echo ============================================
echo.

REM 检查 Python 是否可用
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python，请先安装 Python 3.9+
    echo.
    echo 如果你是普通用户，请使用发布版本：
    echo   双击 dist\DiskCleaner\启动DiskCleaner.bat
    echo.
    pause
    exit /b 1
)

REM 检查依赖
python -c "import flask; import send2trash" >nul 2>&1
if %errorlevel% neq 0 (
    echo [提示] 正在安装依赖...
    pip install flask send2trash
)

echo [启动] 正在启动清理工具...
echo.

REM 启动应用
python "%~dp0app.py"

pause
