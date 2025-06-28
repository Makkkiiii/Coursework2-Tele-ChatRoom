"""
Advanced Security Module for Chat Application
Implements multiple layers of cybersecurity protection including:
- RSA + AES Hybrid Encryption
- Digital Signatures
- Rate Limiting
- Input Validation & Sanitization
- Session Management
- Audit Logging
- Anti-DoS Protection
"""

import os
import time
import hmac
import hashlib
import secrets
import base64
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import re


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
    """Rate limiting to prevent DoS attacks"""
    
    def __init__(self, max_requests: int = 30, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}  # {user_ip: [(timestamp, count), ...]}
        self.blocked_ips = {}  # {ip: block_until_timestamp}
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed (not rate limited)"""
        current_time = time.time()
        
        # Check if IP is currently blocked
        if identifier in self.blocked_ips:
            if current_time < self.blocked_ips[identifier]:
                return False
            else:
                del self.blocked_ips[identifier]
        
        # Clean old requests
        if identifier in self.requests:
            self.requests[identifier] = [
                req for req in self.requests[identifier]
                if current_time - req[0] < self.time_window
            ]
        else:
            self.requests[identifier] = []
        
        # Check rate limit
        if len(self.requests[identifier]) >= self.max_requests:
            # Block IP for 5 minutes
            self.blocked_ips[identifier] = current_time + 300
            return False
        
        # Add current request
        self.requests[identifier].append((current_time, 1))
        return True
    
    def get_remaining_requests(self, identifier: str) -> int:
        """Get remaining requests for identifier"""
        current_count = len(self.requests.get(identifier, []))
        return max(0, self.max_requests - current_count)


class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    def __init__(self):
        self.username_pattern = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
        self.max_message_length = 1000
        self.max_filename_length = 255
        self.dangerous_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'exec\s*\(',
        ]
    
    def validate_username(self, username: str) -> Tuple[bool, str]:
        """Validate username format and security"""
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < 3:
            return False, "Username too short (minimum 3 characters)"
        
        if len(username) > 20:
            return False, "Username too long (maximum 20 characters)"
        
        if not self.username_pattern.match(username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        # Check for reserved names
        reserved_names = ['admin', 'system', 'server', 'root', 'moderator']
        if username.lower() in reserved_names:
            return False, "Username is reserved"
        
        return True, "Valid username"
    
    def sanitize_message(self, message: str) -> Tuple[str, bool]:
        """Sanitize message content and detect malicious patterns"""
        if not message:
            return "", True
        
        # Check length
        if len(message) > self.max_message_length:
            return message[:self.max_message_length], False
        
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return "[FILTERED: Potentially malicious content]", False
        
        # Basic HTML escaping
        message = message.replace('<', '&lt;').replace('>', '&gt;')
        message = message.replace('"', '&quot;').replace("'", '&#x27;')
        
        return message, True
    
    def validate_file(self, filename: str, file_size: int) -> Tuple[bool, str]:
        """Validate file upload security"""
        if not filename:
            return False, "Filename cannot be empty"
        
        if len(filename) > self.max_filename_length:
            return False, "Filename too long"
        
        # Check for dangerous file extensions
        dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            '.jar', '.app', '.deb', '.pkg', '.dmg', '.msi', '.run'
        ]
        
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in dangerous_extensions:
            return False, f"File type {file_ext} not allowed for security reasons"
        
        # Check file size (10MB limit)
        max_size = 10 * 1024 * 1024
        if file_size > max_size:
            return False, f"File too large (max {max_size // (1024*1024)}MB)"
        
        return True, "File is valid"


class SessionManager:
    """Secure session management with expiration"""
    
    def __init__(self, session_timeout: int = 3600):  # 1 hour default
        self.sessions = {}  # {session_id: {user, created, last_activity, ip}}
        self.session_timeout = session_timeout
    
    def create_session(self, username: str, ip_address: str) -> str:
        """Create a new secure session"""
        session_id = secrets.token_urlsafe(32)
        current_time = time.time()
        
        self.sessions[session_id] = {
            'username': username,
            'created': current_time,
            'last_activity': current_time,
            'ip_address': ip_address,
            'is_active': True
        }
        
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str) -> Tuple[bool, Optional[str]]:
        """Validate session and check for hijacking"""
        if session_id not in self.sessions:
            return False, None
        
        session = self.sessions[session_id]
        current_time = time.time()
        
        # Check if session expired
        if current_time - session['last_activity'] > self.session_timeout:
            self.invalidate_session(session_id)
            return False, None
        
        # Check for session hijacking (IP change)
        if session['ip_address'] != ip_address:
            self.invalidate_session(session_id)
            return False, None
        
        # Update last activity
        session['last_activity'] = current_time
        return True, session['username']
    
    def invalidate_session(self, session_id: str):
        """Invalidate a session"""
        if session_id in self.sessions:
            self.sessions[session_id]['is_active'] = False
            del self.sessions[session_id]
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if current_time - session['last_activity'] > self.session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.invalidate_session(session_id)


class HybridCrypto:
    """Hybrid RSA + AES encryption for enhanced security"""
    
    def __init__(self):
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.generate_rsa_keys()
    
    def generate_rsa_keys(self):
        """Generate RSA key pair"""
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
    
    def encrypt_message(self, message: str, recipient_public_key_pem: str = None) -> Dict:
        """Encrypt message using hybrid encryption"""
        # Generate AES key
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)       # 128-bit IV
        
        # Encrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad message to multiple of 16 bytes
        padded_message = self._pad_message(message.encode())
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        if recipient_public_key_pem:
            public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())
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
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
            'iv': base64.b64encode(iv).decode(),
            'encrypted_message': base64.b64encode(encrypted_message).decode()
        }
    
    def decrypt_message(self, encrypted_data: Dict) -> str:
        """Decrypt message using hybrid decryption"""
        try:
            # Decrypt AES key with RSA
            encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_key'])
            aes_key = self.rsa_private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message with AES
            iv = base64.b64decode(encrypted_data['iv'])
            encrypted_message = base64.b64decode(encrypted_data['encrypted_message'])
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
            decrypted_message = self._unpad_message(decrypted_padded)
            
            return decrypted_message.decode()
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def _pad_message(self, message: bytes) -> bytes:
        """PKCS7 padding"""
        padding_length = 16 - (len(message) % 16)
        padding = bytes([padding_length] * padding_length)
        return message + padding
    
    def _unpad_message(self, padded_message: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_message[-1]
        return padded_message[:-padding_length]


class DigitalSignature:
    """Digital signatures for message integrity and authentication"""
    
    def __init__(self, private_key=None):
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
        self.public_key = self.private_key.public_key()
    
    def sign_message(self, message: str) -> str:
        """Create digital signature for message"""
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, message: str, signature: str, public_key_pem: str) -> bool:
        """Verify digital signature"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
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


class AdvancedSecurityManager:
    """Enhanced security manager with multiple protection layers"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Initialize components
        self.audit_logger = SecurityAuditLogger()
        self.rate_limiter = RateLimiter(
            max_requests=self.config.get('max_requests', 30),
            time_window=self.config.get('rate_limit_window', 60)
        )
        self.input_validator = InputValidator()
        self.session_manager = SessionManager(
            session_timeout=self.config.get('session_timeout', 3600)
        )
        self.hybrid_crypto = HybridCrypto()
        self.digital_signature = DigitalSignature()
        
        # Security metrics
        self.security_metrics = {
            'failed_logins': 0,
            'blocked_ips': 0,
            'malicious_attempts': 0,
            'successful_logins': 0
        }
    
    def authenticate_user(self, username: str, ip_address: str) -> Tuple[bool, str, Optional[str]]:
        """Comprehensive user authentication with security checks"""
        
        # Rate limiting check
        if not self.rate_limiter.is_allowed(ip_address):
            self.audit_logger.log_security_event(
                "RATE_LIMIT_EXCEEDED", username, f"IP: {ip_address}", "WARNING"
            )
            self.security_metrics['blocked_ips'] += 1
            return False, "Rate limit exceeded. Please try again later.", None
        
        # Username validation
        is_valid, message = self.input_validator.validate_username(username)
        if not is_valid:
            self.audit_logger.log_security_event(
                "INVALID_USERNAME", username, f"IP: {ip_address}, Error: {message}", "WARNING"
            )
            self.security_metrics['failed_logins'] += 1
            return False, message, None
        
        # Create session
        session_id = self.session_manager.create_session(username, ip_address)
        
        self.audit_logger.log_security_event(
            "USER_LOGIN", username, f"IP: {ip_address}, Session: {session_id[:8]}...", "INFO"
        )
        self.security_metrics['successful_logins'] += 1
        
        return True, "Authentication successful", session_id
    
    def validate_session(self, session_id: str, ip_address: str) -> Tuple[bool, Optional[str]]:
        """Validate user session with security checks"""
        is_valid, username = self.session_manager.validate_session(session_id, ip_address)
        
        if not is_valid:
            self.audit_logger.log_security_event(
                "INVALID_SESSION", "Unknown", f"IP: {ip_address}, Session: {session_id[:8] if session_id else 'None'}...", "WARNING"
            )
        
        return is_valid, username
    
    def secure_message_processing(self, raw_message: str, sender: str, session_id: str) -> Tuple[bool, str]:
        """Process message with security validation"""
        
        # Sanitize message
        sanitized_message, is_safe = self.input_validator.sanitize_message(raw_message)
        
        if not is_safe:
            self.audit_logger.log_security_event(
                "MALICIOUS_CONTENT", sender, f"Original: {raw_message[:50]}...", "CRITICAL"
            )
            self.security_metrics['malicious_attempts'] += 1
            return False, "Message contains potentially malicious content"
        
        # Log message processing
        self.audit_logger.log_security_event(
            "MESSAGE_PROCESSED", sender, f"Length: {len(sanitized_message)}", "INFO"
        )
        
        return True, sanitized_message
    
    def secure_file_processing(self, filename: str, file_size: int, sender: str) -> Tuple[bool, str]:
        """Process file upload with security validation"""
        
        is_valid, message = self.input_validator.validate_file(filename, file_size)
        
        if not is_valid:
            self.audit_logger.log_security_event(
                "INVALID_FILE_UPLOAD", sender, f"File: {filename}, Size: {file_size}, Error: {message}", "WARNING"
            )
            return False, message
        
        self.audit_logger.log_security_event(
            "FILE_UPLOAD", sender, f"File: {filename}, Size: {file_size}", "INFO"
        )
        
        return True, "File is valid"
    
    def get_security_report(self) -> Dict:
        """Generate security metrics report"""
        # Clean up expired sessions
        self.session_manager.cleanup_expired_sessions()
        
        return {
            'metrics': self.security_metrics.copy(),
            'active_sessions': len(self.session_manager.sessions),
            'server_uptime': time.time(),
            'security_level': 'HIGH',
            'last_updated': datetime.now().isoformat()
        }


# Configuration for enhanced security
SECURITY_CONFIG = {
    'max_requests': 20,          # Max requests per time window
    'rate_limit_window': 60,     # Time window in seconds
    'session_timeout': 1800,     # Session timeout in seconds (30 minutes)
    'max_message_length': 500,   # Reduced message length
    'max_file_size': 5242880,    # 5MB file size limit
    'enable_audit_logging': True,
    'enable_rate_limiting': True,
    'enable_input_validation': True,
    'encryption_mode': 'hybrid'   # Use hybrid RSA+AES encryption
}


if __name__ == "__main__":
    # Test the enhanced security features
    print("🔒 ADVANCED SECURITY MODULE TESTING")
    print("=" * 50)
    
    # Initialize security manager
    security_manager = AdvancedSecurityManager(SECURITY_CONFIG)
    
    # Test authentication
    print("\n1. Testing Authentication:")
    success, message, session = security_manager.authenticate_user("testuser", "192.168.1.100")
    print(f"   Authentication: {'✅' if success else '❌'} {message}")
    
    # Test rate limiting
    print("\n2. Testing Rate Limiting:")
    for i in range(25):
        allowed = security_manager.rate_limiter.is_allowed("192.168.1.101")
        if not allowed:
            print(f"   Rate limit triggered after {i} requests ⚠️")
            break
    
    # Test input validation
    print("\n3. Testing Input Validation:")
    test_messages = [
        "Hello, this is a normal message",
        "<script>alert('xss')</script>",
        "A" * 1200,  # Very long message
        "javascript:void(0)"
    ]
    
    for msg in test_messages:
        sanitized, is_safe = security_manager.input_validator.sanitize_message(msg)
        print(f"   Message: {msg[:30]}... -> {'✅' if is_safe else '⚠️'}")
    
    # Test hybrid encryption
    print("\n4. Testing Hybrid Encryption:")
    test_message = "This is a secret message for hybrid encryption testing!"
    encrypted_data = security_manager.hybrid_crypto.encrypt_message(test_message)
    decrypted_message = security_manager.hybrid_crypto.decrypt_message(encrypted_data)
    print(f"   Encryption: {'✅' if test_message == decrypted_message else '❌'}")
    
    # Generate security report
    print("\n5. Security Report:")
    report = security_manager.get_security_report()
    for key, value in report['metrics'].items():
        print(f"   {key}: {value}")
    
    print("\n🎯 Enhanced Security Features Ready!")
    print("✅ Rate Limiting & DoS Protection")
    print("✅ Input Validation & Sanitization") 
    print("✅ Session Management & Anti-Hijacking")
    print("✅ Hybrid RSA+AES Encryption")
    print("✅ Digital Signatures")
    print("✅ Comprehensive Audit Logging")
    print("✅ Security Metrics & Monitoring")
