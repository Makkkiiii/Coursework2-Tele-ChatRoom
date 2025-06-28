# Advanced GUI Chat Application

## Overview

A comprehensive TCP-based chat room application built with Python, featuring modern GUI, end-to-end encryption, file sharing capabilities, and advanced programming concepts including Object-Oriented Programming (OOP) and Data Structures & Algorithms (DSA).

![Advanced Chat Application](https://img.shields.io/badge/Python-3.12%2B-blue.svg)
![GUI](https://img.shields.io/badge/GUI-Tkinter-green.svg)
![Encryption](https://img.shields.io/badge/Encryption-Fernet-red.svg)

![f425c385-dca5-4a4d-97f7-82d79f432a0e](https://github.com/user-attachments/assets/6bf05b95-cbcf-4192-9f07-74d6a594018b)

## ⚡ Quick Start - Verify Encryption Works

**30-second proof:**

```bash
cd Tests
python prove_encryption.py
```

**Complete verification:**

```bash
cd Tests
python verify_encryption.py
```

**GUI demonstration:**

```bash
cd Tests
python encryption_tester.py
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
python secure_server.py
```

**Start the Client:**

```bash
cd Main
python ClientServer.py
```

### Method 2: Quick Encryption Verification

**30-second proof:**

```bash
cd Tests
python prove_encryption.py
```

**Complete verification:**

```bash
cd Tests
python verify_encryption.py
```

**GUI demonstration:**

```bash
cd Tests
python encryption_tester.py
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

### Core Components

#### 1. Security Manager (`SecurityManager`)

```python
# Handles encryption/decryption
security_manager = SecurityManager("password")
encrypted = security_manager.encrypt_message("Hello World")
decrypted = security_manager.decrypt_message(encrypted)
```

#### 2. Message System (`Message`, `MessageQueue`)

```python
# Message creation and queuing
message = Message("user", "content", "text", file_data)
queue = MessageQueue()
queue.put(message)
```

#### 3. User Management (`UserManager`)

```python
# Thread-safe user operations
user_manager = UserManager()
user_manager.add_user("username", socket)
users = user_manager.get_users()
```

#### 4. File Operations (`FileManager`)

```python
# File encoding/decoding
file_manager = FileManager("directory")
file_info = file_manager.encode_file("path/to/file")
saved_path = file_manager.decode_file(file_info)
```

#### 5. Chat History (`ChatHistory`)

```python
# Message storage and search
history = ChatHistory(max_messages=1000)
history.add_message(message)
results = history.search_messages("query")
```

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
python test_chat_app.py
```

### Quick Verification Tools

**Encryption Proof (30 seconds):**

```bash
cd Tests
python prove_encryption.py
```

**Visual Encryption Testing:**

```bash
cd Tests
python encryption_tester.py
```

**Complete Verification:**

```bash
cd Tests
python verify_encryption.py
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

## 🎨 GUI Features

### Modern Design

- **Dark Theme**: Professional dark color scheme
- **Color-coded Messages**: Different colors for user types
- **Real-time Updates**: Live user list and message display
- **Responsive Layout**: Adapts to different screen sizes

### User Experience

- **Intuitive Controls**: Easy-to-use interface
- **Status Indicators**: Connection status and user count
- **File Integration**: Drag-and-drop file sharing
- **Keyboard Shortcuts**: Enter to send messages

## 🛡️ Error Handling

- **Connection Failures**: Automatic reconnection attempts
- **Invalid Messages**: Graceful error display
- **File Errors**: Size/type validation with user feedback
- **Encryption Errors**: Fallback to plain text with warnings
- **Network Issues**: Timeout handling and user notification

## � Project Structure

The project is organized into logical folders to make navigation easier:

```
📁 ProgrammingAlgo2/
├── 📁 Main/                        # Core Application Files
│   ├── ClientServer.py             # 🖥️ Main GUI Client Application
│   └── secure_server.py            # 🔒 Advanced Secure Server with Admin GUI
│
├── 📁 Custom Module/               # Core Libraries & Security
│   ├── chat_core.py                # 🏗️ Core classes (Message, User, Security)
│   ├── advanced_security_fixed.py  # 🛡️ Advanced cybersecurity features
│   └── debug_client.py             # 🐛 Debug client for testing
│
├── 📁 Tests/                       # Testing & Verification Tools
│   ├── test_chat_app.py            # 🧪 Main test suite
│   ├── encryption_tester.py        # 🔬 GUI encryption verification
│   ├── prove_encryption.py         # ⚡ Quick encryption proof (30 sec)
│   ├── verify_encryption.py        # ✅ Complete encryption verification
│   ├── demo_usage.py               # 🎮 Usage demonstration
│   ├── test_gui_fixes.py           # 🔧 GUI testing fixes
│   ├── test_metrics_fix.py         # 📊 Metrics testing
│   └── test_server.py              # 🖧 Server testing utilities
│
├── 📁 Read/                        # Documentation & Guides
│   ├── SECURITY_FEATURES.md        # 🔐 Detailed security documentation
│   ├── ENCRYPTION_VERIFICATION.md  # 🔍 How to verify encryption works
│   ├── GUI_IMPROVEMENTS_SUMMARY.md # 🎨 GUI enhancement details
│   └── METRICS_FIX_SUMMARY.md      # 📈 Metrics and monitoring fixes
│
├── 📁 received_files/              # 📥 Client downloaded files
├── 📁 server_files/                # 📤 Server shared files
├── requirements.txt                # 📦 Python dependencies
└── README.md                      # 📖 This documentation
```

### 📋 Folder Guide

#### 📁 `Main/` - Start Here

**What it contains:** The main applications you'll actually run

- **`secure_server.py`** - The advanced server with admin GUI, security monitoring, and user management
- **`ClientServer.py`** - The client application with modern GUI and encryption features

**How to use:**

1. First run `python secure_server.py`
2. Then run `python ClientServer.py` (can run multiple instances)

#### 📁 `Custom Module/` - Core Engine

**What it contains:** The backbone classes and security systems

- **`chat_core.py`** - Core classes (Message, User, SecurityManager, FileManager)
- **`advanced_security_fixed.py`** - Enterprise-grade security (encryption, rate limiting, audit logging)
- **`debug_client.py`** - Debugging utilities for development

**How to use:** These are imported by the main applications - no need to run directly

#### 📁 `Tests/` - Verification & Testing

**What it contains:** Tools to test and verify everything works

- **`prove_encryption.py`** - Quick 30-second encryption proof for professors
- **`verify_encryption.py`** - Complete encryption verification suite
- **`encryption_tester.py`** - GUI tool to visually test encryption
- **`test_chat_app.py`** - Comprehensive test suite for all features
- **`demo_usage.py`** - Usage demonstration examples

**How to use:**

```bash
cd Tests
python prove_encryption.py    # Quick demo
python encryption_tester.py   # Visual testing
python test_chat_app.py       # Full test suite
```

#### 📁 `Read/` - Documentation Hub

**What it contains:** Detailed documentation and guides

- **`SECURITY_FEATURES.md`** - Complete security documentation
- **`ENCRYPTION_VERIFICATION.md`** - Step-by-step encryption verification
- **`GUI_IMPROVEMENTS_SUMMARY.md`** - GUI features and enhancements
- **`METRICS_FIX_SUMMARY.md`** - Monitoring and metrics details

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

2. **🚀 Quick Demo (30 seconds):**

   ```bash
   cd Tests
   python prove_encryption.py
   ```

3. **🖥️ Run the Application:**

   ```bash
   cd Main
   python secure_server.py    # Terminal 1
   python ClientServer.py     # Terminal 2 (new terminal)
   ```

4. **📚 Read Documentation:**
   - Open `Read/SECURITY_FEATURES.md` for security details
   - Open `Read/ENCRYPTION_VERIFICATION.md` for encryption verification

### For Professors/Reviewers

1. **⚡ Quick Encryption Proof:**

   ```bash
   cd Tests
   python prove_encryption.py
   ```

2. **🔬 Visual Testing:**

   ```bash
   cd Tests
   python encryption_tester.py
   ```

3. **📊 Full Test Suite:**
   ```bash
   cd Tests
   python test_chat_app.py
   ```

### For Developers

1. **🔧 Core Components:**

   - Explore `Custom Module/chat_core.py`
   - Review `Custom Module/advanced_security_fixed.py`

2. **🧪 Testing:**

   - Run tests from `Tests/` folder
   - Check `Tests/test_gui_fixes.py` for GUI testing

3. **📖 Documentation:**
   - Read all files in `Read/` folder
   - Check inline code comments

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

## 🔮 Future Enhancements

- [ ] Voice/Video calling integration
- [ ] Database persistence for chat history
- [ ] User authentication system
- [ ] Private messaging between users
- [ ] Emoji and sticker support
- [ ] Mobile app development
- [ ] Web-based client interface
- [ ] Advanced file preview
- [ ] Message reactions and replies
- [ ] Group chat rooms

## 👥 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request
5. Follow code style guidelines

## 📜 License

This project is created for educational purposes as part of Programming & Algorithm 2 coursework. Feel free to use and modify for learning purposes.

## 🎓 Educational Value

### Programming Concepts Demonstrated

- **Object-Oriented Programming**: Classes, inheritance, encapsulation
- **Data Structures**: Queues, dictionaries, lists, search algorithms
- **Algorithms**: Encryption, file encoding, message routing
- **Concurrency**: Threading, thread-safe operations
- **Network Programming**: TCP sockets, client-server architecture
- **GUI Development**: Event-driven programming, user interface design
- **Software Engineering**: Modular design, error handling, testing

### Skills Developed

- **Python Programming**: Advanced Python concepts and best practices
- **Network Security**: Encryption implementation and secure communication
- **Software Architecture**: Design patterns and system organization
- **User Interface Design**: Creating intuitive and responsive GUIs
- **Testing**: Unit testing and quality assurance
- **Documentation**: Technical writing and code documentation

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
chmod +x server.py
chmod +x client.py
```

### 3. Launching the program:

```
./server.py
./client.py

OR

python3 server.py
python3 client.py
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

## 🔒 How to Verify Encryption is Working

### Quick Command-Line Test

```bash
cd Tests
python verify_encryption.py
```

This runs automated tests to verify:

- Messages are properly encrypted/decrypted
- Original text is not visible in encrypted data
- Network interception simulation
- Professor-friendly demonstration

### GUI Encryption Tester

```bash
cd Tests
python encryption_tester.py
```

Advanced GUI tool with multiple verification methods:

- **🧪 Basic Test**: Simple encrypt/decrypt verification
- **⚡ Before/After**: Side-by-side comparison of original vs encrypted
- **🌐 Network Test**: Shows what encrypted network traffic looks like
- **🔬 Forensic Analysis**: Entropy analysis, frequency analysis, pattern detection

### In-App Testing

1. Start the client (`cd Main && python ClientServer.py`)
2. Click "🔬 Test Encryption" button
3. View real-time encryption/decryption demonstration
4. Check security status indicators

### Quick Professor Demo

```bash
cd Tests
python prove_encryption.py
```

30-second demonstration perfect for showing professors that encryption actually works.

### What Professors Will See

- **Encrypted data**: Completely unreadable scrambled text
- **Original data**: Readable after decryption with correct key
- **Security metrics**: Entropy analysis proves randomness
- **Real-time demo**: Encryption/decryption in action
