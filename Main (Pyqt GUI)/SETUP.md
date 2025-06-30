# TeleChat PyQt Setup Guide

## Quick Start

### Option 1: Using the Batch File (Windows)

1. Double-click `run.bat`
2. Wait for dependencies to install
3. Choose "Start Server" or "Start Client" from the launcher

### Option 2: Manual Setup

1. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Start the launcher:

   ```bash
   python launcher.py
   ```

3. Or run directly:

   ```bash
   # For server
   python PyQt_Server.py

   # For client
   python PyQt_Client.py
   ```

## Dependencies

Make sure you have Python 3.7+ installed, then install:

```bash
pip install PyQt5==5.15.9
pip install cryptography==41.0.7
pip install Pillow==10.0.1
```

## First Run Instructions

### Setting up the Server:

1. Run `PyQt_Server.py`
2. Keep default settings (localhost:12345) or change as needed
3. Click "🚀 Start Server"
4. Monitor connections in the Users tab

### Setting up the Client:

1. Run `PyQt_Client.py`
2. Enter server details (localhost:12345 by default)
3. Choose a username
4. Click "🔗 Connect"
5. Start chatting!

## Features Overview

### Modern Interface

- **Telegram-inspired design**: Clean, modern UI
- **Color-coded messages**: Blue for your messages, green for others
- **Tabbed interface**: Organized features
- **Responsive layout**: Resizable panels

### Security Features

- **End-to-end encryption**: AES-256 encryption
- **Real-time testing**: Test your message encryption
- **Security monitoring**: Live security event tracking
- **Session management**: Secure authentication

### File Sharing

- **Secure transfer**: Encrypted file transmission
- **Size limits**: 10MB maximum file size
- **Type validation**: Blocks dangerous file types
- **Auto-download**: Files saved to received_files folder

## Troubleshooting

### Common Issues:

1. **"ModuleNotFoundError: No module named 'PyQt5'"**

   ```bash
   pip install PyQt5==5.15.9
   ```

2. **"ModuleNotFoundError: No module named 'cryptography'"**

   ```bash
   pip install cryptography==41.0.7
   ```

3. **Connection Failed**

   - Make sure server is running first
   - Check host/port settings match
   - Verify firewall isn't blocking the connection

4. **Server Won't Start**
   - Check if port is already in use
   - Try a different port number
   - Run as administrator if needed

### Performance Tips:

- Close unnecessary applications
- Use localhost for local testing
- Monitor memory usage with many users

## File Structure

```
NewGUI/
├── core.py              # Core functionality (messages, encryption, file handling)
├── security.py          # Advanced security features
├── PyQt_Client.py       # Modern PyQt client application
├── PyQt_Server.py       # Modern PyQt server application
├── launcher.py          # Simple launcher to choose client/server
├── requirements.txt     # Python dependencies
├── run.bat             # Windows batch file for easy startup
├── README.md           # Detailed documentation
└── SETUP.md            # This setup guide
```

## Next Steps

1. **Test the application**: Start server, connect client, send messages
2. **Try file sharing**: Share images, documents, etc.
3. **Explore security**: Use encryption testing features
4. **Monitor server**: Watch live connections and security events
5. **Customize**: Modify colors, sizes, or features as needed

## Support

If you encounter issues:

1. Check the error messages in the security log
2. Verify all dependencies are installed correctly
3. Make sure you're using Python 3.7 or higher
4. Check that ports aren't blocked by firewall

Enjoy your secure chat experience!
