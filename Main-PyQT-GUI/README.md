# TeleChat - Modern PyQt Chat Application

A modern, secure chat application built with PyQt5, featuring end-to-end encryption, file sharing, and advanced security monitoring.

## Features

### 🔒 Security Features

- **End-to-End Encryption**: AES-256 encryption using Fernet
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Message Authentication**: Built-in integrity checking
- **Session Management**: Secure session handling with timeout
- **Rate Limiting**: DoS attack prevention
- **Input Validation**: XSS and injection attack prevention
- **Malicious File Detection**: Real-time deep content analysis and threat blocking
- **Security Audit Logging**: Comprehensive security event tracking

### 💬 Chat Features

- **Real-time Messaging**: Instant message delivery
- **Secure File Sharing**: File transfer with real-time malware detection and threat blocking
- **User Management**: Online user tracking
- **Message History**: Chat history with search capabilities
- **System Messages**: Connection and security notifications

### 🎨 Modern UI Features

- **Black Aesthetic Theme**: Professional dark theme for reduced eye strain
- **WhatsApp/Telegram-style Messages**: Right-aligned blue messages for sender, left-aligned green for receiver
- **Modern Message Bubbles**: Rounded message containers with proper alignment and shadows
- **Responsive Layout**: Fully scalable UI that works on different screen sizes
- **Color-coded Messages**: Intuitive color scheme (Blue: sender, Green: receiver, Gray: system)
- **Tabbed Interface**: Organized features in easy-to-navigate tabs
- **Real-time Status**: Live connection and security status with visual indicators
- **Professional Styling**: Modern dark color scheme with high contrast and readability
- **Improved Sizing**: Larger window dimensions with all tabs and sections fully visible
- **Clean Typography**: Easy-to-read fonts with proper spacing and hierarchy

### 🖥️ Server Features

- **Modern Dark Interface**: Professional black theme matching the client
- **Live Monitoring**: Real-time user and message monitoring with full visibility
- **Security Dashboard**: Comprehensive security event tracking with color-coded alerts
- **Statistics Panel**: Server performance metrics and analytics
- **User Management**: Advanced connect/disconnect tracking with IP logging
- **Improved Layout**: Larger window size ensuring all tabs and sections are fully visible
- **Advanced Logging**: Detailed audit trails with timestamp and event classification
- **Real-time Updates**: Live server statistics and connection monitoring
- **Professional Status Indicators**: Color-coded status bars for different server states

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Install Dependencies

```bash
cd Main-PyQT-GUI
pip install -r requirements.txt
```

### Required Packages

- PyQt5==5.15.9
- cryptography==41.0.7
- Pillow==10.0.1

## Usage

### Starting the Server

```bash
python Main_Server.py
```

1. Configure host and port (default: localhost:12345)
2. Click "🚀 Start Server"
3. Monitor connections and security events in real-time

### Starting the Client

```bash
python Main_Client.py
```

1. Enter server host and port
2. Enter your username
3. Click "🔗 Connect"
4. Start chatting securely!

## Interface Overview

### Client Interface

- **Header**: Connection controls and security status
- **Main Chat**: Modern message display with color coding
- **Tabs**:
  - 👥 Users: Online user list and chat controls
  - 🔒 Security: Encryption status and testing
  - 📁 Files: File sharing and downloads
- **Input Area**: Message typing and send controls

### Server Interface

- **Header**: Server status and live statistics
- **Tabs**:
  - 💬 Messages: Live message monitoring
  - 👥 Users: Connected user management
  - 🔒 Security: Security event log and controls
  - 📊 Statistics: Server performance metrics
- **Controls**: Start/stop server and configuration

## Security Features

### Encryption Testing

- **Real-time Testing**: Test encryption of your actual messages
- **Detailed Analysis**: View original vs encrypted data
- **Security Verification**: Verify message integrity
- **Raw Data Inspection**: Examine encrypted transmission data

### Security Monitoring

- **Live Event Log**: Real-time security event tracking
- **Authentication Monitoring**: Login success/failure tracking
- **Message Validation**: Content security checking
- **File Security**: Upload validation and scanning

### 🛡️ Malicious File Detection

The server performs comprehensive real-time analysis of all uploaded files:

**Detection Capabilities:**

- **Executable Analysis**: Detects PE headers (Windows) and ELF binaries (Linux)
- **Script Detection**: Identifies dangerous PHP, JavaScript, PowerShell, and VBScript code
- **Content Scanning**: Deep analysis of file content for malicious patterns
- **Double Extension Protection**: Prevents `document.pdf.exe` style attacks
- **Size Validation**: Blocks oversized files and potential zip bombs
- **Obfuscation Detection**: Identifies encoded, compressed, or hidden threats

**Real-time Response:**

- **Immediate Blocking**: Malicious files are rejected before reaching clients
- **Alert System**: Critical threats trigger instant server alerts
- **Detailed Logging**: Comprehensive threat analysis and event logging
- **User Feedback**: Clear error messages explaining why files were blocked


## File Sharing

### Supported Features

- **Secure Transfer**: All files encrypted during transmission
- **Size Validation**: 50MB file size limit
- **Type Checking**: Dangerous file type prevention
- **Auto-download**: Received files saved automatically
- **Folder Access**: Quick access to downloads folder

### Security Measures

- **Extension Filtering**: Blocks dangerous file types (.exe, .bat, etc.)
- **Size Limits**: Prevents oversized file attacks
- **Content Validation**: Basic file content checking
- **Path Sanitization**: Prevents directory traversal attacks

## Color Scheme

### Message Colors

- **Your Messages**: Blue (#007bff) - Easy identification
- **Other Messages**: Green (#28a745) - Clear distinction
- **System Messages**: Gray (#6c757d) - Administrative info
- **File Messages**: Green with file icon - Special handling

### UI Colors

- **Primary**: Blue tones for main actions
- **Success**: Green for positive states
- **Warning**: Orange for caution
- **Error**: Red for problems
- **Background**: Light grays for modern look

## Architecture

### Client Architecture

```
Main_Client.py
├── ModernChatGUI (Main Window)
├── ModernChatWidget (Message Display)
├── ChatClient (Network Communication)
├── MessageListeningThread (Background Message Handling)
└── Core Modules (Security, File Management)
```

### Server Architecture

```
Main_Server.py
├── ModernServerGUI (Main Window)
├── SecureChatServer (Server Logic)
├── ServerThread (Background Server Operation)
├── Security Manager (Advanced Security Features)
└── Core Modules (User Management, Message Queue)
```

## Error Handling

### Comprehensive Exception Handling

- **Connection Errors**: Graceful connection failure handling
- **Encryption Errors**: Secure fallback for encryption issues
- **File Errors**: Safe file operation error handling
- **UI Errors**: Robust GUI error management
- **Network Errors**: Connection loss recovery

### User Feedback

- **Error Messages**: Clear, actionable error descriptions
- **Status Updates**: Real-time connection status
- **Security Alerts**: Immediate security event notifications
- **Progress Indicators**: File transfer and operation progress

## Development Notes

### Code Quality

- **Type Hints**: Comprehensive type annotations
- **Documentation**: Detailed function and class documentation
- **Error Handling**: Robust exception management
- **Security Focus**: Security-first development approach

### Performance

- **Threading**: Non-blocking UI with background operations
- **Memory Management**: Efficient resource usage
- **Message Queuing**: Scalable message handling
- **Connection Pooling**: Efficient network resource usage

## Troubleshooting

### Common Issues

1. **PyQt5 Installation Issues**

   ```bash
   pip install --upgrade pip
   pip install PyQt5==5.15.9
   ```

2. **Connection Issues**

   - Check firewall settings
   - Verify host/port configuration
   - Ensure server is running

3. **Encryption Errors**

   - Verify cryptography package installation
   - Check Python version compatibility

4. **File Sharing Issues**
   - Check file permissions
   - Verify file size limits
   - Ensure downloads folder exists

### Support

- Check error messages in security log
- Verify all dependencies are installed
- Ensure Python 3.7+ is being used
- Check network connectivity

## License

This project is part of Programming & Algorithm 2 coursework and is intended for educational purposes.



