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
    """Rate limiting to prevent DoS attacks"""
    
    def __init__(self, max_requests: int = 30, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}  # {user_ip: [timestamp, ...]}
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
                req_time for req_time in self.requests[identifier] 
                if current_time - req_time < self.time_window
            ]
        else:
            self.requests[identifier] = []
        
        # Check rate limit
        if len(self.requests[identifier]) >= self.max_requests:
            # Block IP for double the time window
            self.blocked_ips[identifier] = current_time + (self.time_window * 2)
            return False
        
        # Add current request
        self.requests[identifier].append(current_time)
        return True
    
    def get_remaining_requests(self, identifier: str) -> int:
        """Get remaining requests for identifier"""
        current_requests = len(self.requests.get(identifier, []))
        return max(0, self.max_requests - current_requests)


class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    def __init__(self):
        # Malicious pattern detection
        self.malicious_patterns = [
            r'<script[^>]*>.*?</script>',  # XSS
            r'javascript:',  # JavaScript protocol
            r'vbscript:',   # VBScript protocol
            r'on\w+\s*=',   # Event handlers
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
        self.config = config or SECURITY_CONFIG
        
        # Initialize security components
        self.audit_logger = SecurityAuditLogger()
        self.rate_limiter = RateLimiter(
            max_requests=self.config.get("max_requests", 30),
            time_window=self.config.get("rate_limit_window", 60)
        )
        self.input_validator = InputValidator()
        self.session_manager = SessionManager(
            session_timeout=self.config.get("session_timeout", 3600)
        )
        self.hybrid_crypto = HybridCrypto()
        self.digital_signature = DigitalSignature()
    
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
        
        return True, processed_message
    
    def secure_file_processing(self, filename: str, file_size: int, sender: str) -> Tuple[bool, str]:
        """Process file upload with security validation"""
        
        # Validate filename
        is_valid, message = self.input_validator.validate_filename(filename)
        if not is_valid:
            self.audit_logger.log_security_event(
                "DANGEROUS_FILE", sender, f"File: {filename}", "WARNING"
            )
            return False, message
        
        # Check file size
        max_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10MB
        if file_size > max_size:
            self.audit_logger.log_security_event(
                "OVERSIZED_FILE", sender, f"File: {filename}, Size: {file_size}", "WARNING"
            )
            return False, f"File too large. Maximum size: {max_size} bytes"
        
        # Log file processing
        self.audit_logger.log_security_event(
            "FILE_PROCESSED", sender, f"File: {filename}, Size: {file_size}", "INFO"
        )
        
        return True, "File validation successful"
    
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
                    "max_file_size_bytes": self.config.get("max_file_size", 10 * 1024 * 1024)
                },
                "encryption_status": {
                    "rsa_key_size": 2048,
                    "aes_key_size": 256,
                    "signature_algorithm": "RSA-PSS with SHA-256"
                }
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
    "max_file_size": 10 * 1024 * 1024,  # 10MB
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
    rate_limiter = RateLimiter(max_requests=5, time_window=60)
    for i in range(7):
        allowed = rate_limiter.is_allowed("192.168.1.1")
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


if __name__ == "__main__":
    test_security_components()
