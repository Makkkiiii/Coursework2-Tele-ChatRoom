# Telechat

## Overview

TeleChat, a comprehensive TCP-based chat room application built with Python, featuring modern GUI, end-to-end encryption, file sharing capabilities, and advanced programming concepts including Object-Oriented Programming (OOP) and Data Structures & Algorithms (DSA).

![Advanced Chat Application](https://img.shields.io/badge/Python-3.12%2B-blue.svg)
![GUI](https://img.shields.io/badge/GUI-Tkinter-green.svg)
![Encryption](https://img.shields.io/badge/Encryption-Fernet-red.svg)

![f425c385-dca5-4a4d-97f7-82d79f432a0e](https://github.com/user-attachments/assets/6bf05b95-cbcf-4192-9f07-74d6a594018b)

## ⚡ Quick Start - Verify Encryption Works

**Complete verification:**

```bash
cd Tests
python verify_encryption.py
```

**Usage demonstration:**

```bash
cd Tests
python demo_usage.py
```

**What you'll see:**

- ✅ Secret messages become unreadable scrambled text
- ✅ Original data is perfectly restored after decryption
- ✅ Hackers intercepting network traffic see only gibberish
- ✅ Credit cards, passwords, and sensitive data are protected

## 🚀 Features

### Core Functionality

- **Multi-client TCP server** with concurrent connection handling
- **Modern GUI interface** using Tkinter with custom styling
- **End-to-end encryption** using Fernet symmetric encryption
- **File sharing system** with support for images, documents, and archives
- **Real-time messaging** with message queuing system
- **User management** with join/leave notifications

### Advanced Features

- **Admin controls** for server management (kick users, server shutdown)
- **Message history** with search capabilities
- **Thread-safe operations** for concurrent access
- **Error handling** with graceful degradation
- **File type detection** and size validation
- **Modern UI design** with color-coded messages

### Technical Implementation

- **Object-Oriented Programming (OOP)**: Modular class design with inheritance and encapsulation
- **Data Structures**:
  - Queue for message processing
  - Dictionary for user management
  - List for chat history with search algorithms
- **Design Patterns**: Observer pattern for GUI updates, Factory pattern for message creation
- **Threading**: Concurrent message handling and GUI responsiveness
- **Encryption**: PBKDF2 key derivation with Fernet encryption

## 📋 Requirements

### System Requirements

- Python 3.12 or higher
- Windows/Linux/MacOS
- Minimum 4GB RAM
- Network connectivity for multi-client usage

### Python Dependencies

```
tkinter (built-in)
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
   pip install pillow cryptography
   ```
3. **Verify installation by running tests:**
   ```bash
   cd Tests
   python test_chat_app.py
   ```

## 🚀 Quick Start

### Method 1: Run Main Applications (Recommended)

**Start the Secure Server:**

```bash
cd Main
python Main_Server.py
```

**Start the Client:**

```bash
cd Main
python Main_Client.py
```

### Method 2: Quick Verification

**Complete verification:**

```bash
cd Tests
python verify_encryption.py
```

**Usage demonstration:**

```bash
cd Tests
python demo_usage.py
```

## 📖 Usage Guide

### Server Administration

1. **Start Server**: Configure host/port and click "Start Server"
2. **Monitor Connections**: View connected users in real-time
3. **Admin Controls**: Kick users or shutdown server
4. **View Messages**: Monitor all server communications

### Client Usage

1. **Connect**: Enter server details and username
2. **Send Messages**: Type and press Enter or click Send
3. **Share Files**: Click "Share File" to send documents/images
4. **Download Files**: Received files are automatically saved
5. **View Users**: See all connected users in the sidebar

### File Sharing

- **Supported Types**: Images (PNG, JPG, GIF), Documents (PDF, TXT), Archives (ZIP)
- **Size Limit**: 10MB per file
- **Auto-download**: Files are automatically saved to `received_files/` folder
- **Security**: Files are encrypted during transmission

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

- `text`: Regular chat message
- `file`: File sharing message
- `system`: Server notifications
- `error`: Error messages
- `server_message`: Server announcements

### Data Structures Used

1. **Queue (FIFO)**: Message processing and broadcasting
2. **Dictionary/HashMap**: User management and lookup
3. **List**: Chat history storage and message ordering
4. **Binary Search**: Efficient message searching
5. **Thread-safe Collections**: Concurrent access protection

## 🧪 Testing

Run the comprehensive test suite:

```bash
cd Tests
python Main_Test.py
```

### Quick Verification Tools

**Complete Verification:**

```bash
cd Tests
python verify_encryption.py
```

**Usage Demonstration:**

```bash
cd Tests
python demo_usage.py
```

### Test Coverage

- ✅ Encryption/Decryption functionality
- ✅ Message serialization/deserialization
- ✅ Thread-safe queue operations
- ✅ User management operations
- ✅ File encoding/decoding
- ✅ Chat history and search
- ✅ Error handling scenarios

## 🔧 Configuration

### Server Configuration

- **Default Host**: `localhost`
- **Default Port**: `12345`
- **Max Connections**: `5` (configurable)
- **Message Buffer**: `4096` bytes

### Security Settings

- **Encryption**: Fernet (AES 128)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000
- **Salt**: Configurable (default: static for demo)

### File Sharing Limits

- **Max File Size**: 10MB
- **Supported Types**: All file types
- **Storage Location**: `received_files/` and `server_files/`

## 🔒 Security Features

1. **End-to-End Encryption**: All messages encrypted with Fernet
2. **Key Derivation**: PBKDF2 with SHA-256 hashing
3. **Input Validation**: All user inputs validated and sanitized
4. **File Size Limits**: Prevents DoS attacks via large files
5. **Connection Limits**: Prevents server overload
6. **Error Handling**: Graceful handling of malformed data

## 🛡️ Error Handling

- **Invalid Messages**: Graceful error display
- **File Errors**: Size/type validation with user feedback
- **Encryption Errors**: Fallback to plain text with warnings
- **Network Issues**: Timeout handling and user notification

## 🧩 Project Structure

The project is organized into logical folders to make navigation easier:

```
📁 ProgrammingAlgo2/
├── 📁 Main/                        # Core Application Files
│   ├── Main_Client.py             # 🖥️ Main GUI Client Application
│   ├── Main_Server.py            # 🔒 Advanced Secure Server with Admin GUI
│   ├── core.py                     # 🏗️ Core classes (Message, User, Security)
│   └── security.py                 # 🛡️ Advanced cybersecurity features
│
├── 📁 Tests/                       # Testing & Verification Tools
│   ├── Main_Test.py                # 🧪 Main test suite
│   ├── verify_encryption.py        # ✅ Complete encryption verification
│   ├── demo_usage.py               # 🎮 Usage demonstration
│   ├── chat_core.py                # 🏗️ Core classes for TEST(Message, User, Security)
│   ├── advanced_security_fixed.py  # 🛡️ Advanced cybersecurity features for TEST
│   └── debug_client.py             # 🪲 Debug client for testing
│
├── 📁 Read/                        # Documentation & Guides
│   ├── SECURITY_FEATURES.md        # 🔐 Detailed security documentation
│   └── ENCRYPTION_VERIFICATION.md  # 🔍 How to verify encryption works
│
│
├── 📁 received_files/              # 📥 Client downloaded files
├── 📁 server_files/                # 📤 Server shared files
├── requirements.txt                # 📦 Python dependencies
└── README.md                      # 📖 This documentation
```

### 📋 Folder Guide

#### 📁 `Main/` - Start Here

**What it contains:** The main applications you'll actually run

- **`Main_Server.py`** - The advanced server with admin GUI, security monitoring, and user management
- **`Main_Client.py`** - The client application with modern GUI and encryption features
- **`core.py`** - Core classes (Message, User, SecurityManager, FileManager)
- **`security.py`** - Enterprise-grade security (encryption, rate limiting, audit logging)
- **`core.py & security.py`** - These are imported by the main applications - no need to run directly

**How to use:**

1. First run `python Main_Server.py`
2. Then run `python Main_Client.py` (can run multiple instances)


#### 📁 `Tests/` - Verification & Testing

**What it contains:** Tools to test and verify everything works

- **`Main_Test.py`** - Main test suite for all features
- **`verify_encryption.py`** - Complete encryption verification suite
- **`demo_usage.py`** - Usage demonstration examples
- **`debug_client.py`** - Debug client for testing
- **`chat_core.py`** - Core classes (Message, User, SecurityManager, FileManager)
- **`advanced_security_fixed.py`** - Enterprise-grade security (encryption, rate limiting, audit logging)

**How to use:**

```bash
cd Tests
python Main_Test.py           # Main test suite
python verify_encryption.py  # Encryption verification
python demo_usage.py         # Usage demo
```

#### 📁 `Read/` - Documentation Hub

**What it contains:** Detailed documentation and guides

- **`SECURITY_FEATURES.md`** - Complete security documentation
- **`ENCRYPTION_VERIFICATION.md`** - Step-by-step encryption verification

**How to use:** Open these files to understand specific features in detail

#### 📁 `received_files/` & `server_files/`

**What they contain:** File storage for the chat application

- **`received_files/`** - Files downloaded by clients
- **`server_files/`** - Files shared through the server

**How to use:** These folders are automatically created and managed by the application

## 🎯 Getting Started Guide

### For First-Time Users

1. **📥 Install Dependencies:**

   ```bash
   pip install pillow cryptography
   ```

2. **🚀 Quick Demo:**

   ```bash
   cd Tests
   python verify_encryption.py
   ```

3. **🖥️ Run the Application:**

   ```bash
   cd Main
   python Main_Server.py    # Terminal 1
   python Main_Client.py     # Terminal 2 (new terminal)
   ```

4. **📚 Read Documentation:**
   - Open `Read/SECURITY_FEATURES.md` for security details
   - Open `Read/ENCRYPTION_VERIFICATION.md` for encryption verification

### For Professors/Reviewers

1. **✅ Complete Verification:**

   ```bash
   cd Tests
   python verify_encryption.py
   ```

2. **🎮 Usage Demo:**

   ```bash
   cd Tests
   python demo_usage.py
   ```

3. **📊 Full Test Suite:**
   ```bash
   cd Tests
   python Main_Test.py
   ```

## 🚀 Advanced Usage

### Multiple Clients

1. Start one server instance
2. Run multiple client instances
3. Each client connects with unique username
4. All clients can communicate simultaneously

### File Sharing Workflow

1. Client selects file using "Share File" button
2. File is encoded to base64 and encrypted
3. Server receives and validates file
4. Server broadcasts file to all connected clients
5. Clients automatically decode and save file

### Server Administration

1. Monitor real-time connection status
2. View all messages passing through server
3. Kick problematic users with one click
4. Graceful server shutdown with client notification

## 🐛 Troubleshooting

### Common Issues

**Connection Refused**

- Ensure server is running first
- Check host/port configuration
- Verify firewall settings

**Files Not Sharing**

- Check file size (max 10MB)
- Ensure proper file permissions
- Verify network connectivity

**Encryption Errors**

- Ensure all clients use same password
- Check for corrupted data transmission
- Restart both server and clients

**GUI Not Responding**

- Close and restart application
- Check system resources
- Update Python dependencies

## 📜 License

This project is created for educational purposes as part of the Programming & Algorithm 2 coursework. Feel free to use and modify for learning purposes.

---

**Programming & Algorithm 2 - Advanced Chat Application**
_Built with Python • Featuring OOP, DSA, Encryption, and Modern GUI_

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

# Video Demo

## FOR GUI

https://github.com/user-attachments/assets/bf76838a-9796-4662-b53d-09a767bfef97

### What to Expect

- **Encrypted data**: Completely unreadable scrambled text
- **Original data**: Readable after decryption with correct key
- **Security metrics**: Entropy analysis proves randomness
- **Real-time demo**: Encryption/decryption in action
