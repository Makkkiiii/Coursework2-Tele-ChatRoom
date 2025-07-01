"""
Fixed Advanced Security Module for Chat Application
Implements multiple layers of cybersecurity protection
"""

import os
import time
import hmac
import hashlib
import secrets
import base64
import json
import logging
import re
import html
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List, Union, cast
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class SecurityAuditLogger:
    """Comprehensive security event logging"""
    
    def __init__(self, log_file: str = "security_audit.log"):
        self.log_file = log_file
        self.setup_logging()
    
    def setup_logging(self):
        """Setup secure logging configuration"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('SecurityAudit')
    
    def log_security_event(self, event_type: str, user: str, details: str, 
                          severity: str = "INFO"):
        """Log security-related events"""
        log_entry = {
            "event_type": event_type,
            "user": user,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "severity": severity
        }
        
        if severity == "CRITICAL":
            self.logger.critical(json.dumps(log_entry))
        elif severity == "WARNING":
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))


class RateLimiter:
    """Advanced rate limiting to prevent DoS attacks with different limits for different operations"""
    
    def __init__(self, 
                 message_max_requests: int = 15,  # Stricter for chat messages
                 message_time_window: int = 60,
                 auth_max_requests: int = 5,      # More lenient for auth attempts
                 auth_time_window: int = 300,     # 5 minute window for auth
                 connection_max_requests: int = 10, # Connection attempts
                 connection_time_window: int = 60):
        
        # Different limits for different operation types
        self.limits = {
            'message': {'max_requests': message_max_requests, 'time_window': message_time_window},
            'auth': {'max_requests': auth_max_requests, 'time_window': auth_time_window},
            'connection': {'max_requests': connection_max_requests, 'time_window': connection_time_window}
        }
        
        # Separate tracking for different operation types
        self.requests = {
            'message': {},      # {user_ip: [timestamp, ...]}
            'auth': {},
            'connection': {}
        }
        self.blocked_ips = {
            'message': {},      # {ip: block_until_timestamp}
            'auth': {},
            'connection': {}
        }
    
    def is_allowed(self, identifier: str, operation_type: str = 'message') -> bool:
        """Check if request is allowed (not rate limited)"""
        if operation_type not in self.limits:
            operation_type = 'message'  # Default to message limits
            
        current_time = time.time()
        max_requests = self.limits[operation_type]['max_requests']
        time_window = self.limits[operation_type]['time_window']
        
        # Check if IP is currently blocked for this operation type
        if identifier in self.blocked_ips[operation_type]:
            if current_time < self.blocked_ips[operation_type][identifier]:
                return False
            else:
                del self.blocked_ips[operation_type][identifier]
        
        # Clean old requests for this operation type
        if identifier in self.requests[operation_type]:
            self.requests[operation_type][identifier] = [
                req_time for req_time in self.requests[operation_type][identifier] 
                if current_time - req_time < time_window
            ]
        else:
            self.requests[operation_type][identifier] = []
        
        # Check rate limit
        if len(self.requests[operation_type][identifier]) >= max_requests:
            # Block IP for double the time window
            self.blocked_ips[operation_type][identifier] = current_time + (time_window * 2)
            return False
        
        # Add current request
        self.requests[operation_type][identifier].append(current_time)
        return True
    
    def get_remaining_requests(self, identifier: str, operation_type: str = 'message') -> int:
        """Get remaining requests for identifier and operation type"""
        if operation_type not in self.limits:
            operation_type = 'message'
            
        max_requests = self.limits[operation_type]['max_requests']
        current_requests = len(self.requests[operation_type].get(identifier, []))
        return max(0, max_requests - current_requests)


class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    def __init__(self):
        # Malicious pattern detection
        self.malicious_patterns = [
            r'<script[^>]*>.*?</script>',  # XSS
            r'javascript:',  # JavaScript protocol
            r'vbscript:',   # VBScript protocol
            r'on\w+\s*=',   # Event handlers (onclick, onload, etc.)
            r'on\s+\w+\s*=', # Event handlers with space
            r'eval\s*\(',   # eval() calls
            r'exec\s*\(',   # exec() calls
            r'import\s+os', # OS imports
            r'__import__',  # Dynamic imports
            r'\.\./',       # Directory traversal
            r'\\.\\.\\',    # Windows directory traversal
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                for pattern in self.malicious_patterns]
    
    def validate_username(self, username: str) -> Tuple[bool, str]:
        """Validate username for security"""
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        if len(username) > 32:
            return False, "Username must be less than 32 characters"
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, _ and -"
        
        # Check for reserved names
        reserved = ['admin', 'system', 'server', 'root', 'null', 'undefined']
        if username.lower() in reserved:
            return False, "Username is reserved"
        
        return True, "Valid username"
    
    def validate_message(self, message: str) -> Tuple[bool, str]:
        """Validate and sanitize message content"""
        if not message:
            return False, "Message cannot be empty"
        
        if len(message) > 1000:
            return False, "Message too long (max 1000 characters)"
        
        # Check for malicious patterns
        for pattern in self.compiled_patterns:
            if pattern.search(message):
                return False, "Message contains potentially dangerous content"
        
        # Basic sanitization
        sanitized = html.escape(message) if 'html' in globals() else message
        return True, sanitized
    
    def validate_filename(self, filename: str) -> Tuple[bool, str]:
        """Validate filename for security"""
        if not filename:
            return False, "Filename cannot be empty"
        
        # Check for dangerous characters
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        if any(char in filename for char in dangerous_chars):
            return False, "Filename contains dangerous characters"
        
        # Check file extension
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', 
                              '.js', '.jar', '.vbs', '.ps1', '.php']
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            return False, "File type not allowed"
        
        return True, "Valid filename"


class SessionManager:
    """Secure session management"""
    
    def __init__(self, session_timeout: int = 3600):
        self.session_timeout = session_timeout
        self.sessions = {}  # {session_id: session_data}
        self.user_sessions = {}  # {username: session_id}
    
    def create_session(self, username: str, ip_address: str) -> str:
        """Create a new secure session"""
        session_id = secrets.token_urlsafe(32)
        
        session_data = {
            "username": username,
            "ip_address": ip_address,
            "created_at": datetime.now(),
            "last_activity": datetime.now(),
            "is_active": True
        }
        
        # Remove old session for this user if exists
        if username in self.user_sessions:
            old_session_id = self.user_sessions[username]
            self.sessions.pop(old_session_id, None)
        
        self.sessions[session_id] = session_data
        self.user_sessions[username] = session_id
        
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str) -> Tuple[bool, Optional[str]]:
        """Validate session and return username if valid"""
        if not session_id or session_id not in self.sessions:
            return False, None
        
        session = self.sessions[session_id]
        
        # Check if session is active
        if not session.get("is_active", False):
            return False, None
        
        # Check session timeout
        last_activity = session["last_activity"]
        if datetime.now() - last_activity > timedelta(seconds=self.session_timeout):
            self.invalidate_session(session_id)
            return False, None
        
        # Check IP address (basic session hijacking protection)
        if session["ip_address"] != ip_address:
            self.invalidate_session(session_id)
            return False, None
        
        # Update last activity
        session["last_activity"] = datetime.now()
        
        return True, session["username"]
    
    def invalidate_session(self, session_id: str):
        """Invalidate a session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            username = session.get("username")
            
            # Remove from both dictionaries
            del self.sessions[session_id]
            if username and username in self.user_sessions:
                del self.user_sessions[username]
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        current_time = datetime.now()
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if current_time - session["last_activity"] > timedelta(seconds=self.session_timeout):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.invalidate_session(session_id)


class HybridCrypto:
    """Hybrid RSA + AES encryption for secure communication"""
    
    def __init__(self):
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format"""
        pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def encrypt_message(self, message: str, recipient_public_key_pem: Optional[str] = None) -> Dict:
        """Encrypt message using hybrid encryption"""
        # Generate AES key
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV
        
        # Encrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad message to block size
        padded_message = self._pad_message(message.encode())
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        if recipient_public_key_pem:
            public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())
            # Ensure it's an RSA public key
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Only RSA public keys are supported")
        else:
            public_key = self.rsa_public_key
        
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            "encrypted_message": base64.b64encode(encrypted_message).decode(),
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
            "iv": base64.b64encode(iv).decode()
        }
    
    def decrypt_message(self, encrypted_data: Dict) -> str:
        """Decrypt message using hybrid encryption"""
        try:
            # Decrypt AES key with RSA
            encrypted_aes_key = base64.b64decode(encrypted_data["encrypted_key"])
            aes_key = self.rsa_private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message with AES
            iv = base64.b64decode(encrypted_data["iv"])
            encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
            message = self._unpad_message(padded_message)
            
            return message.decode()
            
        except Exception as e:
            return f"[Decryption Error: {str(e)}]"
    
    def _pad_message(self, message: bytes) -> bytes:
        """PKCS7 padding"""
        block_size = 16
        padding_length = block_size - len(message) % block_size
        padding = bytes([padding_length]) * padding_length
        return message + padding
    
    def _unpad_message(self, padded_message: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_message[-1]
        return padded_message[:-padding_length]


class DigitalSignature:
    """Digital signature for message authentication"""
    
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def sign_message(self, message: str) -> str:
        """Sign a message and return base64 encoded signature"""
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, message: str, signature: str, public_key_pem: Optional[str] = None) -> bool:
        """Verify message signature"""
        try:
            if public_key_pem:
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                # Ensure it's an RSA public key
                if not isinstance(public_key, rsa.RSAPublicKey):
                    return False
            else:
                public_key = self.public_key
            
            signature_bytes = base64.b64decode(signature)
            
            public_key.verify(
                signature_bytes,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')


class AdvancedSecurityManager:
    """Main security manager that coordinates all security components"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or SECURITY_CONFIG.copy()
        
        # Initialize security components
        self.audit_logger = SecurityAuditLogger()
        self.rate_limiter = RateLimiter(
            message_max_requests=self.config.get("max_requests", 15),
            message_time_window=self.config.get("rate_limit_window", 60),
            auth_max_requests=5,
            auth_time_window=300,
            connection_max_requests=10,
            connection_time_window=60
        )
        self.input_validator = InputValidator()
        self.session_manager = SessionManager(
            session_timeout=self.config.get("session_timeout", 3600)
        )
        self.hybrid_crypto = HybridCrypto()
        self.digital_signature = DigitalSignature()
        
        # Security metrics tracking
        self.metrics = {
            "failed_logins": 0,
            "successful_logins": 0,
            "blocked_attempts": 0,
            "malicious_requests": 0,
            "file_uploads": 0,
            "file_downloads": 0,
            "messages_encrypted": 0,
            "messages_decrypted": 0,
            "security_violations": 0,
            "total_connections": 0,
            "active_threats": 0,
            "last_attack_time": None,
            "system_uptime": datetime.now()
        }
        
        # Security event counters
        self.event_counters = {
            "login_attempts": 0,
            "rate_limit_hits": 0,
            "input_validation_failures": 0,
            "session_timeouts": 0,
            "encryption_operations": 0,
            "signature_verifications": 0
        }
        
        self.audit_logger.log_security_event(
            "SECURITY_MANAGER_INITIALIZED", "system", 
            "Security manager started with all components", "INFO"
        )
    
    def increment_metric(self, metric_name: str, increment: int = 1):
        """Safely increment a security metric"""
        if metric_name in self.metrics:
            self.metrics[metric_name] += increment
            
    def increment_event_counter(self, event_name: str, increment: int = 1):
        """Safely increment an event counter"""
        if event_name in self.event_counters:
            self.event_counters[event_name] += increment
            
    def record_security_violation(self, violation_type: str, details: str):
        """Record a security violation"""
        self.increment_metric("security_violations")
        self.metrics["last_attack_time"] = datetime.now()
        self.audit_logger.log_security_event(
            f"SECURITY_VIOLATION_{violation_type}", "system", details, "WARNING"
        )
        
    def record_successful_login(self, username: str):
        """Record a successful login"""
        self.increment_metric("successful_logins")
        self.increment_event_counter("login_attempts")
        
    def record_failed_login(self, username: str):
        """Record a failed login attempt"""
        self.increment_metric("failed_logins")
        self.increment_event_counter("login_attempts")
        
    def record_encryption_operation(self):
        """Record an encryption operation"""
        self.increment_metric("messages_encrypted")
        self.increment_event_counter("encryption_operations")
        
    def record_decryption_operation(self):
        """Record a decryption operation"""
        self.increment_metric("messages_decrypted")
        self.increment_event_counter("encryption_operations")
    
    def authenticate_user(self, username: str, ip_address: str) -> Tuple[bool, str, Optional[str]]:
        """Comprehensive user authentication with security checks"""
        
        # Rate limiting check
        if not self.rate_limiter.is_allowed(ip_address):
            self.audit_logger.log_security_event(
                "RATE_LIMIT_EXCEEDED", username, f"IP: {ip_address}", "WARNING"
            )
            return False, "Too many requests. Please try again later.", None
        
        # Username validation
        is_valid, message = self.input_validator.validate_username(username)
        if not is_valid:
            self.audit_logger.log_security_event(
                "INVALID_USERNAME", username, message, "WARNING"
            )
            return False, message, None
        
        # Create secure session
        session_id = self.session_manager.create_session(username, ip_address)
        
        # Log successful authentication
        self.audit_logger.log_security_event(
            "USER_AUTHENTICATED", username, f"IP: {ip_address}, Session: {session_id[:8]}...", "INFO"
        )
        
        # Update metrics
        self.metrics["successful_logins"] += 1
        self.metrics["total_connections"] += 1
        
        return True, "Authentication successful", session_id
    
    def validate_session(self, session_id: str, ip_address: str) -> Tuple[bool, Optional[str]]:
        """Validate user session"""
        is_valid, username = self.session_manager.validate_session(session_id, ip_address)
        
        if not is_valid:
            self.audit_logger.log_security_event(
                "INVALID_SESSION", "unknown", f"Session: {session_id[:8]}..., IP: {ip_address}", "WARNING"
            )
        
        return is_valid, username
    
    def secure_message_processing(self, message: str, sender: str, session_id: str) -> Tuple[bool, str]:
        """Process message with comprehensive security checks"""
        
        # Validate message content
        is_valid, processed_message = self.input_validator.validate_message(message)
        if not is_valid:
            self.audit_logger.log_security_event(
                "MALICIOUS_MESSAGE", sender, f"Message: {message[:50]}...", "WARNING"
            )
            return False, processed_message
        
        # Log message
        self.audit_logger.log_security_event(
            "MESSAGE_PROCESSED", sender, f"Length: {len(message)}", "INFO"
        )
        
        # Update metrics
        self.metrics["messages_encrypted"] += 1
        
        return True, processed_message
    
    def secure_file_processing(self, filename: str, file_size: int, sender: str, 
                              file_data: Optional[bytes] = None) -> Tuple[bool, str]:
        """Process file upload with comprehensive security validation"""
        
        # 1. Validate filename
        is_valid, message = self.input_validator.validate_filename(filename)
        if not is_valid:
            self.audit_logger.log_security_event(
                "DANGEROUS_FILE", sender, f"File: {filename} - {message}", "WARNING"
            )
            return False, message
        
        # 2. Check file size
        max_size = self.config.get("max_file_size", 50 * 1024 * 1024)  # 50MB
        if file_size > max_size:
            self.audit_logger.log_security_event(
                "OVERSIZED_FILE", sender, f"File: {filename}, Size: {file_size}", "WARNING"
            )
            return False, f"File too large. Maximum size: {max_size} bytes"
        
        # 3. Perform malicious file detection
        malware_check = self._detect_malicious_file(filename, file_size, file_data)
        if not malware_check['safe']:
            threat_details = ', '.join(malware_check['threats'])
            self.audit_logger.log_security_event(
                "MALWARE_DETECTED", sender, 
                f"File: {filename} - Threats: {threat_details}", "CRITICAL"
            )
            return False, f"Malicious file detected: {threat_details}"
        
        # 4. Log warnings if any
        if malware_check['warnings']:
            warning_details = ', '.join(malware_check['warnings'])
            self.audit_logger.log_security_event(
                "FILE_WARNING", sender, 
                f"File: {filename} - Warnings: {warning_details}", "WARNING"
            )
        
        # 5. Log successful file processing
        self.audit_logger.log_security_event(
            "FILE_PROCESSED", sender, f"File: {filename}, Size: {file_size}", "INFO"
        )
        
        # Update metrics
        self.metrics["file_uploads"] += 1
        
        return True, "File validation successful"
    
    def _detect_malicious_file(self, filename: str, file_size: int, 
                              file_data: Optional[bytes] = None) -> Dict:
        """Comprehensive malicious file detection"""
        results = {
            'safe': True,
            'threats': [],
            'warnings': [],
            'scan_details': {}
        }
        
        # Define dangerous file extensions
        dangerous_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbe',
            '.js', '.jse', '.jar', '.ps1', '.ps2', '.reg', '.msi', '.dll',
            '.app', '.deb', '.rpm', '.run', '.bin'
        }
        
        # Define suspicious patterns in file content
        malicious_patterns = [
            (b'MZ\x90\x00', 'PE Executable Header'),
            (b'!<arch>', 'Archive/Library File'),
            (b'<?php', 'PHP Script'),
            (b'<script', 'JavaScript Code'),
            (b'powershell', 'PowerShell Command'),
            (b'cmd /c', 'Command Execution'),
            (b'eval(', 'Code Evaluation'),
            (b'exec(', 'Code Execution'),
            (b'system(', 'System Command'),
            (b'shell_exec', 'Shell Execution'),
            (b'passthru', 'Command Passthrough'),
            (b'base64_decode', 'Base64 Decoding'),
            (b'gzinflate', 'Compression/Obfuscation'),
            (b'str_rot13', 'String Rotation/Obfuscation'),
            (b'CreateObject', 'Object Creation (VBScript/JS)'),
            (b'WScript.Shell', 'Windows Script Shell'),
            (b'XMLHttpRequest', 'HTTP Request (JS)'),
            (b'ActiveXObject', 'ActiveX Object'),
            (b'document.cookie', 'Cookie Stealing'),
            (b'window.location', 'Redirection Attack'),
            (b'javascript:', 'JavaScript Protocol'),
            (b'data:', 'Data URL Scheme'),
            (b'vbscript:', 'VBScript Protocol')
        ]
        
        # 1. Extension Check
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in dangerous_extensions:
            results['threats'].append(f"Dangerous file extension: {file_ext}")
            results['safe'] = False
        
        # 2. Double Extension Check
        if filename.count('.') > 1:
            parts = filename.lower().split('.')
            for i, part in enumerate(parts[:-1]):
                if f".{parts[i+1]}" in dangerous_extensions:
                    results['threats'].append("Double extension attack detected")
                    results['safe'] = False
                    break
        
        # 3. Filename Analysis
        filename_lower = filename.lower()
        
        # Check for suspicious filename patterns
        suspicious_names = [
            'autorun', 'setup', 'install', 'update', 'patch', 'crack',
            'keygen', 'serial', 'activator', 'loader', 'trojan', 'virus',
            'malware', 'backdoor', 'rootkit', 'keylogger', 'ransomware'
        ]
        
        for suspicious in suspicious_names:
            if suspicious in filename_lower:
                results['warnings'].append(f"Suspicious filename pattern: {suspicious}")
        
        # Check filename length
        if len(filename) > 255:
            results['threats'].append("Filename too long (possible buffer overflow)")
            results['safe'] = False
        
        # Check for null bytes in filename
        if '\x00' in filename:
            results['threats'].append("Null byte in filename")
            results['safe'] = False
        
        # Check for control characters
        if any(ord(c) < 32 for c in filename if c not in ['\t', '\n', '\r']):
            results['warnings'].append("Control characters in filename")
        
        # 4. File Size Analysis
        if file_size == 0:
            results['warnings'].append("Zero-byte file")
        elif file_size > 100 * 1024 * 1024:  # > 100MB
            results['warnings'].append("Very large file size")
        
        # 5. Content Analysis (if file data is provided)
        if file_data:
            results['scan_details']['content_scanned'] = True
            
            # Check file signature/magic numbers
            if len(file_data) >= 4:
                header = file_data[:10]
                
                # PE Executable check
                if header.startswith(b'MZ'):
                    results['threats'].append("Windows executable detected")
                    results['safe'] = False
                
                # ELF Executable check
                elif header.startswith(b'\x7fELF'):
                    results['threats'].append("Linux executable detected")
                    results['safe'] = False
                
                # Java class file
                elif header.startswith(b'\xca\xfe\xba\xbe'):
                    results['warnings'].append("Java class file detected")
                
                # PDF with JavaScript
                elif b'PDF' in header and b'/JS' in file_data[:1024]:
                    results['warnings'].append("PDF with JavaScript detected")
            
            # Scan for malicious patterns in content
            content_lower = file_data.lower()
            for pattern, description in malicious_patterns:
                if pattern in content_lower:
                    if any(word in description.lower() for word in ['execution', 'command', 'shell', 'script']):
                        results['threats'].append(f"Malicious pattern: {description}")
                        results['safe'] = False
                    else:
                        results['warnings'].append(f"Suspicious pattern: {description}")
            
            # Check for obfuscation indicators
            obfuscation_indicators = [
                (lambda data: data.count(b'\\x') > 10, "Hex encoding detected"),
                (lambda data: data.count(b'%') > 20, "URL encoding detected"),
                (lambda data: len([c for c in data if c > 127]) > len(data) * 0.3, "High entropy content"),
                (lambda data: b'base64' in data and len(data) > 1000, "Large base64 content")
            ]
            
            for check_func, description in obfuscation_indicators:
                try:
                    if check_func(file_data):
                        results['warnings'].append(description)
                except:
                    pass
                    
            # Archive bomb detection (simplified)
            if filename_lower.endswith(('.zip', '.rar', '.7z', '.tar.gz')):
                if file_size < 1024 and b'compressed' not in filename_lower.encode():
                    results['warnings'].append("Potentially compressed bomb (very small archive)")
        
        else:
            results['scan_details']['content_scanned'] = False
            results['warnings'].append("File content not available for deep scanning")
        
        # 6. Advanced Heuristics
        
        # Polyglot file detection
        if any(ext in filename_lower for ext in ['.html', '.htm']) and \
           any(ext in filename_lower for ext in ['.js', '.php', '.asp']):
            results['warnings'].append("Potential polyglot file")
        
        # Steganography detection (basic)
        if filename_lower.endswith(('.jpg', '.png', '.gif', '.bmp')) and file_data:
            if len(file_data) > 10 * 1024 * 1024:  # > 10MB image
                results['warnings'].append("Large image file (possible steganography)")
        
        # Log scan results
        scan_summary = {
            'safe': results['safe'],
            'threat_count': len(results['threats']),
            'warning_count': len(results['warnings']),
            'file_size': file_size,
            'extension': file_ext
        }
        results['scan_details'].update(scan_summary)
        
        return results
    
    def get_security_report(self) -> Dict:
        """Generate comprehensive security report"""
        try:
            # Get current timestamp
            current_time = datetime.now()
            
            # Collect security metrics
            report = {
                "timestamp": current_time.isoformat(),
                "system_status": "active",
                "security_components": {
                    "audit_logger": "operational",
                    "rate_limiter": "operational", 
                    "input_validator": "operational",
                    "session_manager": "operational",
                    "hybrid_crypto": "operational",
                    "digital_signature": "operational"
                },
                "active_sessions": len(self.session_manager.sessions),
                "rate_limit_status": {
                    "total_tracked_ips": len(self.rate_limiter.requests),
                    "currently_blocked_ips": list(self.rate_limiter.blocked_ips.keys()),
                    "active_request_counts": {ip: len(reqs) for ip, reqs in self.rate_limiter.requests.items()}
                },
                "security_config": {
                    "max_requests_per_window": self.config.get("max_requests", 30),
                    "rate_limit_window_seconds": self.config.get("rate_limit_window", 60),
                    "session_timeout_seconds": self.config.get("session_timeout", 3600),
                    "max_file_size_bytes": self.config.get("max_file_size", 50 * 1024 * 1024)
                },
                "encryption_status": {
                    "rsa_key_size": 2048,
                    "aes_key_size": 256,
                    "signature_algorithm": "RSA-PSS with SHA-256"
                },
                "metrics": self.metrics,
                "event_counters": self.event_counters,
                "uptime_seconds": (datetime.now() - self.metrics["system_uptime"]).total_seconds()
            }
            
            # Log the report generation
            self.audit_logger.log_security_event(
                "SECURITY_REPORT_GENERATED", "system", 
                f"Report contains {len(report)} sections", "INFO"
            )
            
            return report
            
        except Exception as e:
            # Log error and return minimal report
            self.audit_logger.log_security_event(
                "SECURITY_REPORT_ERROR", "system", 
                f"Error generating report: {str(e)}", "ERROR"
            )
            
            return {
                "timestamp": datetime.now().isoformat(),
                "system_status": "error",
                "error": f"Failed to generate security report: {str(e)}",
                "security_components": {
                    "audit_logger": "unknown",
                    "rate_limiter": "unknown",
                    "input_validator": "unknown", 
                    "session_manager": "unknown",
                    "hybrid_crypto": "unknown",
                    "digital_signature": "unknown"
                }
            }


# Default security configuration
SECURITY_CONFIG = {
    "max_requests": 30,
    "rate_limit_window": 60,
    "session_timeout": 3600,
    "max_file_size": 50 * 1024 * 1024,  # 50MB
    "enable_audit_logging": True,
    "enable_rate_limiting": True,
    "enable_input_validation": True,
    "enable_session_management": True
}


def test_security_components():
    """Test all security components"""
    print("🔐 TESTING ADVANCED SECURITY COMPONENTS")
    print("=" * 50)
    
    # Test SecurityAuditLogger
    logger = SecurityAuditLogger("test_security.log")
    logger.log_security_event("TEST_EVENT", "test_user", "Testing security logging")
    print("✅ Security Audit Logger - OK")
    
    # Test RateLimiter
    rate_limiter = RateLimiter(message_max_requests=5, message_time_window=60)
    for i in range(7):
        allowed = rate_limiter.is_allowed("192.168.1.1", "message")
        if i < 5:
            assert allowed, f"Request {i+1} should be allowed"
        else:
            assert not allowed, f"Request {i+1} should be blocked"
    print("✅ Rate Limiter - OK")
    
    # Test InputValidator
    validator = InputValidator()
    
    # Username tests
    valid, msg = validator.validate_username("test_user")
    assert valid, "Valid username should pass"
    
    valid, msg = validator.validate_username("admin")
    assert not valid, "Reserved username should fail"
    
    # Message tests
    valid, msg = validator.validate_message("Hello world!")
    assert valid, "Valid message should pass"
    
    valid, msg = validator.validate_message("<script>alert('xss')</script>")
    assert not valid, "XSS attempt should fail"
    
    print("✅ Input Validator - OK")
    
    # Test SessionManager
    session_mgr = SessionManager(session_timeout=10)
    session_id = session_mgr.create_session("test_user", "192.168.1.1")
    
    valid, username = session_mgr.validate_session(session_id, "192.168.1.1")
    assert valid and username == "test_user", "Valid session should work"
    
    valid, username = session_mgr.validate_session(session_id, "192.168.1.2")
    assert not valid, "Different IP should fail"
    
    print("✅ Session Manager - OK")
    
    # Test HybridCrypto
    crypto = HybridCrypto()
    test_message = "This is a secret message!"
    
    encrypted = crypto.encrypt_message(test_message)
    decrypted = crypto.decrypt_message(encrypted)
    
    assert decrypted == test_message, "Encryption/decryption should work"
    print("✅ Hybrid Crypto - OK")
    
    # Test DigitalSignature
    signer = DigitalSignature()
    test_message = "Message to sign"
    
    signature = signer.sign_message(test_message)
    is_valid = signer.verify_signature(test_message, signature)
    
    assert is_valid, "Digital signature should verify"
    print("✅ Digital Signature - OK")
    
    # Test AdvancedSecurityManager
    security_mgr = AdvancedSecurityManager(SECURITY_CONFIG)
    
    # Test authentication
    success, msg, session_id = security_mgr.authenticate_user("test_user", "192.168.1.1")
    assert success, "Valid authentication should succeed"
    assert session_id is not None, "Session ID should be provided"
    
    # Test session validation
    valid, username = security_mgr.validate_session(session_id, "192.168.1.1")
    assert valid and username == "test_user", "Session validation should work"
    
    # Test message processing
    valid, processed = security_mgr.secure_message_processing("Hello!", "test_user", session_id)
    assert valid, "Valid message should be processed"
    
    # Test file processing
    valid, msg = security_mgr.secure_file_processing("document.pdf", 1024, "test_user")
    assert valid, "Valid file should be accepted"
    
    valid, msg = security_mgr.secure_file_processing("malware.exe", 1024, "test_user")
    assert not valid, "Dangerous file should be rejected"
    
    print("✅ Advanced Security Manager - OK")
    
    print("\n🎉 ALL SECURITY COMPONENTS TESTED SUCCESSFULLY!")
    print("=" * 50)


class TestSecuritySuite:
    """Comprehensive security testing suite with authentication"""
    
    def __init__(self):
        # Import here to avoid circular imports
        from core import SecurityManager, AuthenticationManager
        
        self.test_results = {}
        self.server_password = "TestServer2025!"
        self.security_manager = SecurityManager(self.server_password)
        self.auth_manager = AuthenticationManager(self.security_manager)
    
    def run_all_tests(self):
        """Run all security tests"""
        print("=" * 60)
        print("RUNNING ENHANCED SECURITY TESTS WITH AUTHENTICATION")
        print("=" * 60)
        
        self.test_password_authentication()
        self.test_encryption_strength()
        self.test_brute_force_resistance()
        self.test_session_management()
        self.test_message_integrity()
        self.test_salt_validation()
        self.test_authentication_manager()
        
        self.print_results()
    
    def test_password_authentication(self):
        """Test password authentication mechanism"""
        print("\n1. Testing Password Authentication...")
        
        # Test correct password
        correct_result = self.security_manager.verify_password(self.server_password)
        
        # Test wrong passwords
        wrong_passwords = [
            "wrongpassword",
            "TestServer2024!",  # Close but wrong
            "",                 # Empty
            "testserver2025!",  # Wrong case
            "TestServer2025",   # Missing special char
        ]
        
        wrong_results = [self.security_manager.verify_password(pwd) for pwd in wrong_passwords]
        
        # Test case sensitivity
        case_test = self.security_manager.verify_password("testserver2025!")
        
        success = correct_result and not any(wrong_results) and not case_test
        self.test_results["Password Authentication"] = success
        
        print(f"   ✓ Correct password accepted: {correct_result}")
        print(f"   ✓ Wrong passwords rejected: {not any(wrong_results)}")
        print(f"   ✓ Case sensitivity working: {not case_test}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_encryption_strength(self):
        """Test encryption strength and consistency"""
        print("\n2. Testing Encryption Strength...")
        
        test_messages = [
            "Simple message",
            "Message with special chars: !@#$%^&*()",
            "Very long message " * 100,
            "Unicode test: 你好世界 🌍",
            ""  # Empty message
        ]
        
        all_passed = True
        for msg in test_messages:
            try:
                encrypted = self.security_manager.encrypt_message(msg)
                decrypted = self.security_manager.decrypt_message(encrypted)
                
                # Test that encryption produces different results each time
                encrypted2 = self.security_manager.encrypt_message(msg)
                different_ciphertext = encrypted != encrypted2 if msg else True
                
                passed = (decrypted == msg) and different_ciphertext
                all_passed &= passed
                
                print(f"   ✓ '{msg[:20]}{'...' if len(msg) > 20 else ''}': {'PASS' if passed else 'FAIL'}")
            except Exception as e:
                print(f"   ✗ Error with '{msg[:20]}': {e}")
                all_passed = False
        
        self.test_results["Encryption Strength"] = all_passed
        print(f"   Result: {'PASS' if all_passed else 'FAIL'}")
    
    def test_brute_force_resistance(self):
        """Test resistance to brute force attacks"""
        print("\n3. Testing Brute Force Resistance...")
        
        import time
        
        # Test common passwords
        common_passwords = [
            "password", "123456", "admin", "root", "guest",
            "password123", "qwerty", "abc123", "test", "user"
        ]
        
        start_time = time.time()
        failed_attempts = 0
        
        for pwd in common_passwords:
            if not self.security_manager.verify_password(pwd):
                failed_attempts += 1
        
        end_time = time.time()
        time_taken = end_time - start_time
        
        # Each verification should take reasonable time due to PBKDF2
        reasonable_time = time_taken > 0.1  # Should take more than 0.1 seconds for 10 attempts
        all_rejected = failed_attempts == len(common_passwords)
        
        success = all_rejected and reasonable_time
        self.test_results["Brute Force Resistance"] = success
        
        print(f"   ✓ Common passwords rejected: {failed_attempts}/{len(common_passwords)}")
        print(f"   ✓ Time taken: {time_taken:.3f}s (should be > 0.1s)")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_session_management(self):
        """Test authentication session management"""
        print("\n4. Testing Session Management...")
        
        # Create mock sockets that inherit from object (compatible with set operations)
        class MockSocket:
            def __init__(self, socket_id):
                self.id = socket_id
        
        mock_socket1 = MockSocket(1)
        mock_socket2 = MockSocket(2)
        
        # Test authentication
        auth1 = self.auth_manager.authenticate_client(mock_socket1, self.server_password)
        auth2 = self.auth_manager.authenticate_client(mock_socket2, "wrong_password")
        
        # Test session checking
        is_auth1 = self.auth_manager.is_authenticated(mock_socket1)
        is_auth2 = self.auth_manager.is_authenticated(mock_socket2)
        
        # Test logout
        self.auth_manager.logout_client(mock_socket1)
        is_auth1_after_logout = self.auth_manager.is_authenticated(mock_socket1)
        
        success = auth1 and not auth2 and is_auth1 and not is_auth2 and not is_auth1_after_logout
        self.test_results["Session Management"] = success
        
        print(f"   ✓ Correct password authentication: {auth1}")
        print(f"   ✓ Wrong password rejection: {not auth2}")
        print(f"   ✓ Session tracking: {is_auth1 and not is_auth2}")
        print(f"   ✓ Logout functionality: {not is_auth1_after_logout}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_message_integrity(self):
        """Test message integrity and tampering detection"""
        print("\n5. Testing Message Integrity...")
        
        original_message = "Important secure message"
        encrypted = self.security_manager.encrypt_message(original_message)
        
        # Test normal decryption
        decrypted = self.security_manager.decrypt_message(encrypted)
        normal_success = decrypted == original_message
        
        # Test tampering detection by modifying encrypted data
        tampered_encrypted = encrypted[:-5] + "XXXXX"  # Modify last 5 characters
        tampered_result = self.security_manager.decrypt_message(tampered_encrypted)
        tampering_detected = "[Decryption Error:" in tampered_result
        
        # Test with completely invalid data
        invalid_result = self.security_manager.decrypt_message("invalid_base64_data!")
        invalid_detected = "[Decryption Error:" in invalid_result
        
        success = normal_success and tampering_detected and invalid_detected
        self.test_results["Message Integrity"] = success
        
        print(f"   ✓ Normal decryption: {normal_success}")
        print(f"   ✓ Tampering detection: {tampering_detected}")
        print(f"   ✓ Invalid data handling: {invalid_detected}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_salt_validation(self):
        """Test salt implementation and consistency"""
        print("\n6. Testing Salt Implementation...")
        
        # Import here to avoid circular imports
        from core import SecurityManager
        
        # Create two SecurityManager instances with same password
        sm1 = SecurityManager(self.server_password)
        sm2 = SecurityManager(self.server_password)
        
        # They should produce same auth hashes (same salt)
        same_auth_hash = sm1.auth_hash == sm2.auth_hash
        
        # They should be able to decrypt each other's messages
        test_msg = "Cross-instance test"
        encrypted_by_sm1 = sm1.encrypt_message(test_msg)
        decrypted_by_sm2 = sm2.decrypt_message(encrypted_by_sm1)
        cross_decrypt = decrypted_by_sm2 == test_msg
        
        # Different passwords should produce different hashes
        sm3 = SecurityManager("different_password")
        different_auth_hash = sm1.auth_hash != sm3.auth_hash
        
        success = same_auth_hash and cross_decrypt and different_auth_hash
        self.test_results["Salt Implementation"] = success
        
        print(f"   ✓ Consistent auth hashes: {same_auth_hash}")
        print(f"   ✓ Cross-instance decryption: {cross_decrypt}")
        print(f"   ✓ Different passwords produce different hashes: {different_auth_hash}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def test_authentication_manager(self):
        """Test comprehensive authentication manager functionality"""
        print("\n7. Testing Authentication Manager...")
        
        # Test multiple client authentication
        clients = []
        for i in range(3):
            client = type('MockSocket', (), {'id': i})()
            clients.append(client)
        
        # Authenticate 2 clients correctly, 1 incorrectly
        auth_results = [
            self.auth_manager.authenticate_client(clients[0], self.server_password),
            self.auth_manager.authenticate_client(clients[1], self.server_password),
            self.auth_manager.authenticate_client(clients[2], "wrong_password")
        ]
        
        # Check counts
        expected_count = 2  # Only 2 should be authenticated
        actual_count = self.auth_manager.get_authenticated_count()
        
        # Test bulk logout
        self.auth_manager.logout_client(clients[0])
        count_after_logout = self.auth_manager.get_authenticated_count()
        
        success = (auth_results[0] and auth_results[1] and not auth_results[2] and 
                  actual_count == expected_count and count_after_logout == expected_count - 1)
        
        self.test_results["Authentication Manager"] = success
        
        print(f"   ✓ Multiple client auth: {auth_results[0] and auth_results[1]}")
        print(f"   ✓ Wrong password rejection: {not auth_results[2]}")
        print(f"   ✓ Correct count tracking: {actual_count == expected_count}")
        print(f"   ✓ Logout count update: {count_after_logout == expected_count - 1}")
        print(f"   Result: {'PASS' if success else 'FAIL'}")
    
    def print_results(self):
        """Print comprehensive test results"""
        print("\n" + "=" * 60)
        print("ENHANCED SECURITY TEST RESULTS")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results.values() if result)
        total = len(self.test_results)
        
        for test_name, result in self.test_results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{test_name:<30} {status}")
        
        print("-" * 60)
        print(f"Total: {passed}/{total} tests passed")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("🎉 ALL SECURITY TESTS PASSED! System is secure for deployment.")
        else:
            print("⚠️  Some tests failed. Review security implementation.")
        
        print("=" * 60)


def run_enhanced_security_tests():
    """Run comprehensive security tests with authentication"""
    test_suite = TestSecuritySuite()
    test_suite.run_all_tests()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--enhanced":
        # Run enhanced security tests with authentication
        run_enhanced_security_tests()
    else:
        # Run basic security component tests
        test_security_components()
    run_enhanced_security_tests()
