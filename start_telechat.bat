@echo off
echo 🔒 TeleChat Application - Modern PyQt Interface
echo ==============================================
echo.
echo Available options:
echo 1. Start Server
echo 2. Start Client
echo 3. Install Requirements
echo.
set /p choice="Choose option (1-3): "

if "%choice%"=="1" (
    echo 🚀 Starting TeleChat Server...
    cd NewGUI
    python PyQt_Server.py
    pause
) else if "%choice%"=="2" (
    echo 📱 Starting TeleChat Client...
    cd NewGUI
    python PyQt_Client.py
    pause
) else if "%choice%"=="3" (
    echo 📦 Installing requirements...
    cd NewGUI
    pip install -r requirements.txt
    echo Installation complete!
    pause
) else (
    echo Invalid option. Please choose 1, 2, or 3.
    pause
)
