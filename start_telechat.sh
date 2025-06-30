#!/bin/bash
echo "🔒 TeleChat Application - Modern PyQt Interface"
echo "=============================================="
echo ""
echo "Available options:"
echo "1. Start Server"
echo "2. Start Client"
echo "3. Start Both (Server first, then Client)"
echo ""
read -p "Choose option (1-3): " choice

case $choice in
    1)
        echo "🚀 Starting TeleChat Server..."
        cd NewGUI
        python PyQt_Server.py
        ;;
    2)
        echo "📱 Starting TeleChat Client..."
        cd NewGUI
        python PyQt_Client.py
        ;;
    3)
        echo "🚀 Starting TeleChat Server in background..."
        cd NewGUI
        python PyQt_Server.py &
        SERVER_PID=$!
        echo "Server started with PID: $SERVER_PID"
        sleep 2
        echo "📱 Starting TeleChat Client..."
        python PyQt_Client.py
        echo "Stopping server..."
        kill $SERVER_PID 2>/dev/null
        ;;
    *)
        echo "Invalid option. Please choose 1, 2, or 3."
        ;;
esac
