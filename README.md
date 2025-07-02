# TeleChat

## Overview

TeleChat is a professional-grade, TCP-based secure chat room application built with Python, featuring modern PyQt5 GUI, password authentication, advanced cybersecurity features, file sharing capabilities, and enterprise-level security monitoring. This application demonstrates advanced programming concepts including Object-Oriented Programming (OOP), Data Structures & Algorithms (DSA), and comprehensive cybersecurity implementation.

![Advanced Chat Application](https://img.shields.io/badge/Python-3.12%2B-blue.svg)
![GUI](https://img.shields.io/badge/GUI-PyQt5-green.svg)
![Encryption](https://img.shields.io/badge/Encryption-AES256-red.svg)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-orange.svg)
![Authentication](https://img.shields.io/badge/Auth-Password%20Protected-purple.svg)

![f425c385-dca5-4a4d-97f7-82d79f432a0e](https://github.com/user-attachments/assets/6bf05b95-cbcf-4192-9f07-74d6a594018b)

## ⚡ Quick Start - Verify Security Works

**Complete security verification:**

```bash
cd Main-PyQT-GUI
python comprehensive_security_test.py
```

**Start the secure server:**

```bash
cd Main-PyQT-GUI
python Main_Server.py
```

**Start the client:**

```bash
cd Main-PyQT-GUI
python Main_Client.py
```

**What you'll see:**

- 🔐 Password-protected server with authentication challenges
- 🛡️ Real-time security monitoring and threat detection
- 🚫 XSS/dangerous message blocking with live warnings
- 📊 Rate limiting preventing spam and DoS attacks
- 🔍 Malicious file detection and blocking
- 📋 Comprehensive security audit logging
- ⚠️ Live security alerts and notifications
- 👮 Admin controls for user management and server monitoring

## 🚀 Features

### Enterprise Security Features

- **🔐 Password Authentication**: Server requires password for access with brute-force protection
- **🛡️ Advanced Threat Detection**: Real-time XSS, injection, and malicious content blocking
- **📊 Smart Rate Limiting**: Prevents spam and DoS attacks with intelligent message filtering
- **🔍 Malicious File Detection**: Advanced file scanning with size and type validation
- **📋 Security Audit Logging**: Comprehensive logging of all security events and threats
- **⚠️ Real-time Security Alerts**: Live monitoring with instant threat notifications
- **🚫 Input Validation**: Complete sanitization of all user inputs and data
- **👮 Admin Controls**: Server administrator can kick users and monitor all activities

### Core Functionality

- **Multi-client TCP server** with concurrent connection handling and authentication
- **Modern PyQt5 GUI interface** with professional dark theme and responsive design
- **Enterprise-grade encryption** using AES-256 with PBKDF2 key derivation
- **Secure file sharing system** with malware detection and size validation
- **Real-time messaging** with thread-safe message queuing and delivery confirmation
- **Advanced user management** with authentication status and session tracking

### Advanced Technical Features

- **Security Dashboard**: Real-time monitoring of connections, threats, and security events
- **Multi-tier Rate Limiting**: Different limits for messages, authentication, and connections
- **Session Management**: Secure session handling with timeout protection
- **File Transfer Validation**: Server-side file acceptance/rejection with client feedback
- **Thread-safe Operations**: Concurrent access protection with proper synchronization
- **Error Handling**: Comprehensive error handling with graceful degradation
- **Modern UI Design**: Professional interface with color-coded security levels

### Technical Implementation

- **Object-Oriented Programming (OOP)**: Advanced modular design with inheritance, encapsulation, and polymorphism
- **Data Structures**:
  - Multi-tier rate limiting with separate queues for different operation types
  - Thread-safe dictionaries for user and session management
  - Circular buffers for message history with efficient search algorithms
  - Priority queues for security event processing
- **Design Patterns**: Observer pattern for security monitoring, Factory pattern for message creation, Singleton for security manager
- **Advanced Threading**: Concurrent message handling, security monitoring, and GUI responsiveness
- **Enterprise Encryption**: AES-256 with PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
- **Cybersecurity**: XSS detection, input validation, malware scanning, audit logging
- **Authentication**: Password-based server access with session management
- **Network Security**: Rate limiting, connection validation, protocol message filtering

## 📋 Requirements

### System Requirements

- Python 3.12 or higher
- Windows/Linux/MacOS
- Minimum 4GB RAM
- Network connectivity for multi-client usage

### Python Dependencies

```
PyQt5>=5.15.0
pillow>=9.0.0
cryptography>=3.4.8
socket (built-in)
threading (built-in)
json (built-in)
```

## 🛠️ Installation

1. **Clone or download the project files**
2. **Install required packages:**
   ```bash
   pip install PyQt5 pillow cryptography
   ```
3. **Verify installation by running tests:**
   ```bash
   cd Main-PyQT-GUI
   python comprehensive_security_test.py
   ```

## 🚀 Quick Start

### Method 1: Run Main Applications (Recommended)

**Start the Secure Server:**

```bash
cd Main-PyQT-GUI
python Main_Server.py
```

**Start the Client:**

```bash
cd Main-PyQT-GUI
python Main_Client.py
```

### Method 2: Quick Verification

**Complete security verification:**

```bash
cd Main-PyQT-GUI
python comprehensive_security_test.py
```

**Usage demonstration:**

```bash
cd Tests
python demo_usage.py
```

## 📖 Usage Guide

### Server Administration

1. **Start Server**: Configure host/port, set server password, and click "Start Server"
2. **Password Protection**: Server requires password authentication before allowing connections
3. **Security Dashboard**: Monitor real-time security events, rate limiting, and threat detection
4. **User Management**: View connected users, authentication status, and kick problematic users
5. **Message Monitoring**: View all server communications with security filtering
6. **Security Logs**: Comprehensive audit trail of all security events and threats
7. **Rate Limiting**: Automatic protection against spam and DoS attacks

### Client Usage

1. **Connect**: Enter server details, username, and server password
2. **Authentication**: Complete password challenge to gain access
3. **Send Messages**: Type messages with automatic XSS/threat detection
4. **Share Files**: Click "Share File" to send documents/images (with malware detection)
5. **Security Warnings**: Receive notifications when messages/files are blocked
6. **Download Files**: Received files are automatically saved with security validation
7. **View Users**: See all connected users in the sidebar with authentication status

### Security Features in Action

- **XSS Detection**: Messages containing dangerous content are blocked and warnings are shown
- **Rate Limiting**: Rapid message sending is automatically throttled
- **File Security**: Malicious files are detected and blocked with user notification
- **Authentication**: Password protection prevents unauthorized access
- **Audit Logging**: All security events are logged for monitoring

### File Sharing

- **Supported Types**: Images (PNG, JPG, GIF), Documents (PDF, TXT), Archives (ZIP)
- **Size Limit**: 10MB per file with server-side validation
- **Security Scanning**: Advanced malware detection and file type validation
- **Auto-download**: Files are automatically saved to `received_files/` folder
- **Encryption**: Files are encrypted during transmission with AES-256
- **Server Feedback**: Explicit success/failure notifications for file transfers
- **Architecture**: Server acts as a relay only - files are not stored on the server

### File Sharing Architecture

The application uses a **relay-based file sharing model** for security and efficiency:

#### How File Sharing Works

1. **Client Side (Sender)**:

   - User selects a file to share
   - Client encodes file to base64 and encrypts
   - File data is sent to server with metadata

2. **Server Side (Relay & Security)**:

   - Server validates file size and type for security
   - Advanced malware detection scans file content and metadata
   - Server sends explicit success/failure notifications to sender
   - Server does NOT store the file locally (relay-only architecture)
   - Server immediately relays approved files to all other clients
   - Only validation, security scanning, and relay - no persistent storage

3. **Client Side (Receivers)**:
   - Clients receive the file data from server (only if approved)
   - Clients decode and save file to `received_files/` folder
   - Receive security notifications if files are blocked
   - Each client manages their own file storage with validation

#### Benefits of Relay Architecture

- **Privacy**: Server never stores user files
- **Security**: Advanced malware detection and file validation
- **Storage Efficiency**: Server doesn't need file storage space
- **Attack Surface**: Reduces security risks on server
- **Scalability**: Server memory usage remains constant
- **Simplicity**: No file cleanup or management needed on server
- **User Feedback**: Clear success/failure notifications for all file operations

## 🏗️ Architecture

### Network Protocol

#### Message Format

```json
{
    "type": "message_type",
    "data": {
        "id": "message_id",
        "sender": "username",
        "content": "message_content",
        "type": "text|file|system",
        "file_data": {...},
        "timestamp": "ISO_timestamp"
    }
}
```

#### Message Types

- `text`: Regular chat message (subject to XSS detection)
- `file`: File sharing message (subject to malware detection)
- `system`: Server notifications and security alerts
- `error`: Error messages and warnings
- `server_message`: Server announcements
- `warning`: Security warnings (XSS/malware detection)
- `file_success`: File transfer confirmation messages
- `auth_challenge`: Password authentication requests
- `auth_response`: Authentication responses

### Data Structures Used

1. **Rate Limiting Queues**: Multi-tier FIFO queues for different operation types (messages, auth, connections)
2. **User Management Dictionary**: Thread-safe HashMap for user lookup and session management
3. **Security Event Lists**: Ordered message history with efficient searching and filtering
4. **Authentication Tracking**: Binary search trees for efficient session validation
5. **Thread-safe Collections**: Concurrent access protection with proper synchronization
6. **File Transfer Tracking**: Dictionary-based tracking of file transfer states and confirmations

## 🧪 Testing

Run the comprehensive security test suite:

```bash
cd Main-PyQT-GUI
python comprehensive_security_test.py
```

### Quick Verification Tools

**Complete Security Verification:**

```bash
cd Main-PyQT-GUI
python comprehensive_security_test.py
```

**Legacy Test Suite:**

```bash
cd Tests
python Main_Test.py
```

### Test Coverage

- ✅ Password authentication and session management
- ✅ XSS detection and dangerous message blocking
- ✅ Rate limiting and DoS protection
- ✅ Malicious file detection and blocking
- ✅ Encryption/Decryption functionality
- ✅ Message serialization/deserialization
- ✅ Thread-safe queue operations
- ✅ User management and kick functionality
- ✅ File encoding/decoding with security validation
- ✅ Security event logging and audit trails
- ✅ Error handling scenarios

## 🔧 Configuration

### Server Configuration

- **Default Host**: `localhost`
- **Default Port**: `12345`
- **Max Connections**: `5` (configurable)
- **Message Buffer**: `4096` bytes

### Security Settings

- **Password Protection**: Server requires password authentication (configurable)
- **Encryption**: AES-256 with Fernet implementation
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Rate Limiting**: Configurable limits for messages (5/min), auth (3/min), connections (10/min)
- **XSS Detection**: Advanced regex patterns for dangerous content detection
- **File Security**: Malware detection, size limits (10MB), type validation
- **Session Management**: Secure session handling with timeout protection
- **Audit Logging**: Comprehensive security event logging with timestamps

### File Sharing Limits

- **Max File Size**: 10MB with server-side validation
- **Supported Types**: All file types with security scanning
- **Storage Location**: `received_files/` (client-side only)
- **Security Scanning**: Advanced malware detection and validation
- **Transfer Confirmation**: Explicit success/failure notifications

## 🔒 Security Features

1. **Password Authentication**: Server requires password for access with brute-force protection
2. **Advanced Threat Detection**: Real-time XSS, injection, and malicious content blocking
3. **Smart Rate Limiting**: Prevents spam and DoS attacks with intelligent message filtering
4. **Malicious File Detection**: Advanced file scanning with size and type validation
5. **Security Audit Logging**: Comprehensive logging of all security events and threats
6. **Real-time Security Alerts**: Live monitoring with instant threat notifications
7. **Input Validation**: Complete sanitization of all user inputs and data
8. **Admin Controls**: Server administrator can kick users and monitor all activities
9. **Session Management**: Secure session handling with timeout protection
10. **End-to-End Encryption**: All messages encrypted with AES-256

## 🛡️ Error Handling

- **Authentication Failures**: Clear feedback for incorrect passwords
- **Security Violations**: Immediate warnings for XSS/malicious content
- **File Rejection**: Detailed notifications for blocked files
- **Rate Limiting**: Clear messages when limits are exceeded
- **Invalid Messages**: Graceful error display with security logging
- **File Errors**: Size/type validation with user feedback and server notifications
- **Encryption Errors**: Secure fallback handling with audit logging
- **Network Issues**: Timeout handling and user notification with reconnection support

## 🧩 Project Structure

The project is organized into logical folders to make navigation easier:

```
📁 ProgrammingAlgo2/
├── 📁 Main-PyQT-GUI/                 # Core PyQt Application Files
│   ├── Main_Client.py               # 🖥️ Main PyQt5 Client Application with Security
│   ├── Main_Server.py              # 🔒 Advanced Secure Server with Admin GUI
│   ├── core.py                     # 🏗️ Core classes (Message, User, Security)
│   ├── security.py                 # 🛡️ Enterprise security features
│   ├── launcher.py                 # 🚀 Application launcher
│   ├── comprehensive_security_test.py # 🧪 Complete security test suite
│   └── received_files/             # 📥 Client downloaded files
│
├── 📁 Main-Tkinter-GUI/             # Legacy Tkinter Implementation
│   ├── Main_Client.py              # 🖥️ Tkinter Client (Legacy)
│   ├── Main_Server.py              # 🔒 Tkinter Server (Legacy)
│   ├── core.py                     # 🏗️ Core classes for Tkinter
│   ├── security.py                 # 🛡️ Security features for Tkinter
│   └── received_files/             # 📥 Client downloaded files
│
├── 📁 Tests/                       # Testing & Verification Tools
│   ├── Main_Test.py                # 🧪 Legacy test suite
│   ├── verify_encryption.py        # ✅ Encryption verification
│   ├── demo_usage.py               # 🎮 Usage demonstration
│   ├── chat_core.py                # 🏗️ Core classes for testing
│   ├── advanced_security_fixed.py  # 🛡️ Security features for testing
│   └── debug_client.py             # 🪲 Debug client for testing
│
├── 📁 Read/                        # Documentation & Guides
│   ├── SECURITY_FEATURES.md        # 🔐 Detailed security documentation
│   └── ENCRYPTION_VERIFICATION.md  # 🔍 How to verify encryption works
│
├── 📁 received_files/              # 📥 Global file storage
├── requirements.txt                # 📦 Python dependencies
└── README.md                      # 📖 This documentation
```

### 📋 Folder Guide

#### 📁 `Main-PyQT-GUI/` - **PRIMARY APPLICATION** (Start Here)

**What it contains:** The main PyQt5 applications with full security features

- **`Main_Server.py`** - Advanced server with admin GUI, security monitoring, password protection, and user management
- **`Main_Client.py`** - Modern PyQt5 client with security features, file sharing, and threat detection
- **`core.py`** - Core classes (Message, User, SecurityManager, FileManager) with advanced features
- **`security.py`** - Enterprise-grade security (encryption, rate limiting, XSS detection, malware scanning)
- **`launcher.py`** - Application launcher for easy startup
- **`comprehensive_security_test.py`** - Complete security verification suite

**How to use:**

1. First run `python Main_Server.py`
2. Then run `python Main_Client.py` (can run multiple instances)
3. Use `python comprehensive_security_test.py` to verify all security features

#### 📁 `Main-Tkinter-GUI/` - Legacy Implementation

**What it contains:** Legacy Tkinter version (for compatibility)

- Similar structure but with Tkinter GUI instead of PyQt5
- Basic security features without advanced monitoring

#### 📁 `Tests/` - Verification & Testing

**What it contains:** Tools to test and verify everything works

- **`Main_Test.py`** - Legacy test suite
- **`verify_encryption.py`** - Encryption verification
- **`demo_usage.py`** - Usage demonstration examples
- **`chat_core.py`** - Core classes for testing
- **`advanced_security_fixed.py`** - Security features for testing

**How to use:**

```bash
cd Tests
python Main_Test.py           # Legacy test suite
python verify_encryption.py  # Encryption verification
python demo_usage.py         # Usage demo
```

#### 📁 `Read/` - Documentation Hub

**What it contains:** Detailed documentation and guides

- **`SECURITY_FEATURES.md`** - Complete security documentation
- **`ENCRYPTION_VERIFICATION.md`** - Step-by-step encryption verification

**How to use:** Open these files to understand specific features in detail

#### 📁 `received_files/`

**What they contain:** File storage for client downloads

- **`received_files/`** - Files downloaded by clients
- **`Main-PyQT-GUI/received_files/`** - PyQt client file storage
- **`Main-Tkinter-GUI/received_files/`** - Tkinter client file storage

**How to use:** These folders are automatically created and managed by the client applications. The server acts as a relay and does not store files.

## 🎯 Getting Started Guide

### For First-Time Users

1. **📥 Install Dependencies:**

   ```bash
   pip install PyQt5 pillow cryptography
   ```

2. **🚀 Quick Security Demo:**

   ```bash
   cd Main-PyQT-GUI
   python comprehensive_security_test.py
   ```

3. **🖥️ Run the PyQt Application:**

   ```bash
   cd Main-PyQT-GUI
   python Main_Server.py    # Terminal 1
   python Main_Client.py    # Terminal 2 (new terminal)
   ```

4. **📚 Read Documentation:**
   - Open `Read/SECURITY_FEATURES.md` for security details
   - Open `Read/ENCRYPTION_VERIFICATION.md` for encryption verification

### For Professors/Reviewers

1. **✅ Complete Security Verification:**

   ```bash
   cd Main-PyQT-GUI
   python comprehensive_security_test.py
   ```

2. **🎮 Usage Demo:**

   ```bash
   cd Tests
   python demo_usage.py
   ```

3. **📊 Legacy Test Suite:**

   ```bash
   cd Tests
   python Main_Test.py
   ```

4. **🖥️ Try the Application:**
   ```bash
   cd Main-PyQT-GUI
   python Main_Server.py    # Start server with password protection
   python Main_Client.py    # Start client and test security features
   ```

## 🚀 Advanced Usage

### Multiple Clients with Security

1. Start one server instance with password protection
2. Run multiple client instances (each needs server password)
3. Each client connects with unique username and authentication
4. All clients can communicate simultaneously with security monitoring
5. Server admin can monitor all connections and security events

### Secure File Sharing Workflow

1. Client selects file using "Share File" button
2. File is encoded to base64 and encrypted with AES-256
3. Server receives and performs security validation (malware detection, size limits)
4. Server sends explicit success/failure notification to sender
5. Server broadcasts approved files to all connected clients
6. Clients automatically decode and save secure files
7. All file transfers are logged for security audit

### Server Administration & Security

1. Monitor real-time connection status and authentication events
2. View security dashboard with threat detection and rate limiting
3. Review comprehensive security logs and audit trails
4. Kick problematic users with one click
5. Monitor XSS/malware detection events
6. Graceful server shutdown with client notification

## 🐛 Troubleshooting

### Common Issues

**Authentication Failed**

- Ensure you have the correct server password
- Check if server is configured with password protection
- Verify server is running and accepting connections

**Connection Refused**

- Ensure server is running first
- Check host/port configuration
- Verify firewall settings
- Confirm server password is set correctly

**Security Warnings**

- XSS/dangerous content warnings are normal security features
- File blocking indicates malware detection is working
- Rate limiting messages show DoS protection is active

**Files Not Sharing**

- Check file size (max 10MB)
- Ensure file passes malware detection
- Verify network connectivity
- Check server security logs for rejection reasons

**GUI Not Responding**

- Close and restart application
- Check system resources
- Update Python and PyQt5 dependencies
- Verify no conflicting processes

## 📜 License

This project is created for educational purposes as part of the Programming & Algorithm 2 coursework. Feel free to use and modify for learning purposes.

---

**Programming & Algorithm 2 - Enterprise Security Chat Application**
_Built with Python • Featuring PyQt5 GUI, Enterprise Security, OOP, DSA, Encryption, and Advanced Cybersecurity_

![image](https://github.com/Makkkiiii/Password-Generator/assets/148240694/8d509ad9-1d1a-467b-89d0-7d479f42d2d4)

- Download the zip file.
- Unzip the zip file.
- Run it on your machine.

## 2. FOR LINUX

![image](https://github.com/Makkkiiii/Password-Generator/assets/148240694/87344c86-3469-437f-a53f-cae2531541f8)

### Use **Text Editor** like:

- Mousepad
- Vim
- Nano
- Gedit

### 1. Clone the repository:

```
git clone https://github.com/Makkkiiii/Coursework2-Tele-ChatRoom.git
```

### 2. Compiling

You can just make the script executable by adding the following command

```
#!/usr/bin/env python
```

Give permissions

```
chmod +x Main_Server.py
chmod +x Main_Client.py
```

### 3. Launching the program:

```
cd Main-PyQT-GUI
python3 Main_Server.py
python3 Main_Client.py
```

Or for legacy Tkinter version:

```
cd Main-Tkinter-GUI
python3 Main_Server.py
python3 Main_Client.py
```

## 3. FOR MAC

![image](https://github.com/Makkkiiii/Password-Generator/assets/148240694/1c970412-db98-4f30-a1bf-b87ae00f8ce3)

_It is similar to Linux and Windows._

You can use coding software, a terminal, or just clone it.

Use the desired text editor.

## Steps

Follow the given instructions inside the program

## Tools Used

![image](https://github.com/Makkkiiii/Password-Generator/assets/148240694/cb19d6e4-0c03-4c73-839a-b5f126ceaa7c)

This program was written in Python using Visual Studio Code.

### What to Expect

- **🔐 Password Protection**: Server requires authentication for access
- **🛡️ Security Monitoring**: Real-time threat detection and prevention
- **🚫 XSS Protection**: Dangerous messages are blocked with warnings
- **📊 Rate Limiting**: Automatic spam and DoS protection
- **🔍 File Security**: Malware detection and validation
- **📋 Audit Logging**: Comprehensive security event tracking
- **💻 Modern GUI**: Professional PyQt5 interface with dark theme
- **🔒 Encrypted Data**: All communications secured with AES-256
- **⚠️ Security Alerts**: Live notifications of security events

# Video Demo
