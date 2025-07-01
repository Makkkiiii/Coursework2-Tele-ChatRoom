#!/usr/bin/env python3
"""
Test script to verify that rate limiting is now properly differentiated by operation type
"""

import sys
import os
import time
sys.path.append(os.path.dirname(__file__))

from security import RateLimiter

def test_rate_limiting_fix():
    """Test that different operation types have different rate limits"""
    
    print("🧪 Testing Rate Limiting Fix...")
    
    # Create rate limiter with different limits for different operations
    rate_limiter = RateLimiter(
        message_max_requests=3,    # Very low for testing
        message_time_window=60,
        auth_max_requests=5,       # Higher for auth
        auth_time_window=60,
        connection_max_requests=2, # Very low for testing
        connection_time_window=60
    )
    
    test_ip = "192.168.1.100"
    
    print("\n📊 Testing message rate limiting...")
    # Test message rate limiting (3 requests max)
    for i in range(5):
        allowed = rate_limiter.is_allowed(test_ip, "message")
        print(f"  Message request {i+1}: {'✅ ALLOWED' if allowed else '❌ BLOCKED'}")
        if i < 3:
            assert allowed, f"Message request {i+1} should be allowed"
        else:
            assert not allowed, f"Message request {i+1} should be blocked"
    
    print("\n🔐 Testing auth rate limiting (different limit)...")
    # Test auth rate limiting (5 requests max, separate counter)
    for i in range(7):
        allowed = rate_limiter.is_allowed(test_ip, "auth")
        print(f"  Auth request {i+1}: {'✅ ALLOWED' if allowed else '❌ BLOCKED'}")
        if i < 5:
            assert allowed, f"Auth request {i+1} should be allowed"
        else:
            assert not allowed, f"Auth request {i+1} should be blocked"
    
    print("\n🔗 Testing connection rate limiting (separate counter)...")
    # Test connection rate limiting (2 requests max, separate counter)
    for i in range(4):
        allowed = rate_limiter.is_allowed(test_ip, "connection")
        print(f"  Connection request {i+1}: {'✅ ALLOWED' if allowed else '❌ BLOCKED'}")
        if i < 2:
            assert allowed, f"Connection request {i+1} should be allowed"
        else:
            assert not allowed, f"Connection request {i+1} should be blocked"
    
    # Test with a different IP to ensure isolation
    test_ip2 = "192.168.1.101"
    print(f"\n🌐 Testing with different IP ({test_ip2})...")
    
    # Should be allowed since it's a different IP
    allowed = rate_limiter.is_allowed(test_ip2, "message")
    print(f"  Different IP message request: {'✅ ALLOWED' if allowed else '❌ BLOCKED'}")
    assert allowed, "Different IP should be allowed"
    
    allowed = rate_limiter.is_allowed(test_ip2, "auth")
    print(f"  Different IP auth request: {'✅ ALLOWED' if allowed else '❌ BLOCKED'}")
    assert allowed, "Different IP auth should be allowed"
    
    allowed = rate_limiter.is_allowed(test_ip2, "connection")
    print(f"  Different IP connection request: {'✅ ALLOWED' if allowed else '❌ BLOCKED'}")
    assert allowed, "Different IP connection should be allowed"
    
    print("\n✅ All rate limiting tests passed!")
    print("📝 Summary:")
    print("  - Message rate limiting: 3 requests/60s")
    print("  - Auth rate limiting: 5 requests/60s") 
    print("  - Connection rate limiting: 2 requests/60s")
    print("  - Different operation types are tracked separately")
    print("  - Different IPs are tracked separately")
    print("\n🎯 Rate limiting fix verified successfully!")

if __name__ == "__main__":
    test_rate_limiting_fix()
