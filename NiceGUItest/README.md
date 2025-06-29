# 🌐 NiceGUI TeleChat - Modern Web-Based Secure Chat

A modern, web-based version of the TeleChat application built with **NiceGUI**, featuring the same advanced security and encryption as the desktop version but with a sleek web interface.

## 🚀 What's New in NiceGUI Version

### ✨ **Modern Web Interface**

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-time Updates**: WebSocket-based communication
- **Dark Theme**: Professional, modern appearance
- **No Installation**: Runs in any web browser

### 🔒 **Same Advanced Security**

- All encryption features preserved from original
- **AES-256 Encryption** with Fernet
- **PBKDF2 Key Derivation** (100,000 iterations)
- **Advanced Security Manager** with threat detection
- **Session Management** and audit logging

### 🌟 **Improved User Experience**

- **Cross-platform**: Works on any device with a browser
- **Multiple Sessions**: Multiple users can connect from different devices
- **Better Responsiveness**: Faster UI updates
- **Mobile-friendly**: Touch-optimized interface

## 📋 Quick Start

### 1. Install Dependencies

```bash
cd NiceGUItest
pip install -r requirements.txt
```

### 2. Start the Server

```bash
python NiceGUI_Server.py
```

- Server will start on `http://localhost:8081`
- Open in your browser to access server admin panel

### 3. Start Client(s)

```bash
python NiceGUI_Client.py
```

- Client will start on `http://localhost:8080`
- Open in multiple browser tabs/windows for multiple users

## 🔄 Comparison: Tkinter vs NiceGUI

| Feature               | Tkinter Version | NiceGUI Version       |
| --------------------- | --------------- | --------------------- |
| **Platform**          | Desktop only    | Any web browser       |
| **Installation**      | Python + deps   | Python + browser      |
| **UI Framework**      | Tkinter         | Modern web components |
| **Real-time**         | Threading       | WebSockets            |
| **Mobile Support**    | ❌              | ✅                    |
| **Multiple Sessions** | One per machine | Multiple per device   |
| **Deployment**        | Local install   | Web server            |
| **Security**          | ✅ Same         | ✅ Same               |

## 🛡️ Security Features (Unchanged)

All security features from the original are preserved:

### 🔐 **Encryption**

- **AES-256 (Fernet)**: Military-grade encryption
- **PBKDF2**: Key derivation with 100,000 iterations
- **Message Authentication**: Built-in integrity checking

### 🛡️ **Advanced Protection**

- **Rate Limiting**: 30 requests/minute per IP
- **DoS Protection**: Connection and message limits
- **Input Validation**: XSS and injection prevention
- **Session Management**: Secure user sessions
- **Audit Logging**: All security events logged

### 📊 **Monitoring**

- **Real-time Metrics**: Live security statistics
- **Threat Detection**: Automatic blocking of suspicious activity
- **Admin Controls**: User management and kick functionality

## 🎯 Usage Guide

### Server Interface

1. **Start Server**: Click "🚀 Start Secure Server"
2. **Monitor Users**: View connected users in real-time
3. **Security Events**: Watch live security monitoring
4. **Admin Actions**: Kick users or view metrics

### Client Interface

1. **Connect**: Enter host, port, and username
2. **Chat**: Send encrypted messages instantly
3. **Share Files**: Upload and share files securely
4. **Verify Encryption**: Test and view your encryption

## 🔧 Configuration

### Server Settings

- **Host**: Default `localhost` (change for network access)
- **Port**: Default `8081` (server admin interface)
- **Security**: All features enabled by default

### Client Settings

- **Server Connection**: Connect to any server instance
- **Port**: Default `8080` (client interface)
- **Multiple Clients**: Open multiple browser tabs

## 🌐 Network Deployment

### Local Network

```bash
# Server (accessible from network)
python NiceGUI_Server.py --host 0.0.0.0 --port 8081

# Clients connect to server IP
# http://[server-ip]:8081 (admin)
# http://[server-ip]:8080 (client)
```

### Production Deployment

- Deploy with **Nginx** reverse proxy
- Use **SSL/TLS** certificates
- Configure **firewall** rules
- Set up **monitoring** and logging

## 📁 File Structure

```
NiceGUItest/
├── NiceGUI_Client.py       # 🌐 Web-based client
├── NiceGUI_Server.py       # 🌐 Web-based server
├── core.py                 # 🏗️ Backend logic (unchanged)
├── security.py             # 🛡️ Security features (unchanged)
├── requirements.txt        # 📦 Dependencies
└── README.md              # 📖 This file
```

## 🚀 Advantages of NiceGUI Version

### For Users

- **No Installation**: Just open a web browser
- **Cross-platform**: Works on Windows, Mac, Linux, mobile
- **Familiar Interface**: Web-based, modern design
- **Multiple Devices**: Chat from phone, tablet, desktop

### For Developers

- **Easier Deployment**: Web server model
- **Better Scaling**: Handle more concurrent users
- **Modern Framework**: Built on FastAPI/Uvicorn
- **Real-time**: WebSocket communication

### For Administrators

- **Remote Administration**: Manage server from anywhere
- **Better Monitoring**: Web-based dashboards
- **Easier Updates**: Deploy without client updates
- **Network Ready**: Built for multi-user environments

## 🔄 Migration from Tkinter

The NiceGUI version maintains **100% compatibility** with the backend:

- Same encryption algorithms
- Same security features
- Same message protocols
- Same file sharing

**Only the UI layer has changed** - all core functionality is identical.

## 🎉 Benefits Summary

✅ **Modern web interface** replaces desktop GUI  
✅ **Cross-platform compatibility** (any device)  
✅ **Real-time WebSocket** communication  
✅ **Mobile-friendly** responsive design  
✅ **Multiple simultaneous users** per device  
✅ **Network deployment ready**  
✅ **Same advanced security** features  
✅ **No client installation** required  
✅ **Professional appearance**  
✅ **Easier administration**

The NiceGUI version brings your secure chat application into the modern web era while maintaining all the security and functionality you've built! 🚀
