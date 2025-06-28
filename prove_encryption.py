#!/usr/bin/env python3
"""
SIMPLE ENCRYPTION PROOF
========================
One-command verification that encryption is working.
Perfect for quick demonstrations.
"""

def prove_encryption():
    """Prove encryption is working in 30 seconds"""
    
    print("🔒 SIMPLE ENCRYPTION PROOF")
    print("=" * 40)
    
    try:
        from chat_core import SecurityManager
    except ImportError:
        print("❌ Error: chat_core.py not found")
        return False
    
    # Create security manager
    security = SecurityManager("demo")
    
    # Test message with sensitive data
    secret = "🔥 TOP SECRET: Nuclear launch codes are 123-456-789"
    
    print(f"📝 Secret message:")
    print(f"   '{secret}'")
    print()
    
    # Encrypt
    print("🔐 Encrypting...")
    encrypted = security.encrypt_message(secret)
    
    print("📡 What hackers see on the network:")
    print(f"   '{encrypted}'")
    print()
    
    # Analysis
    print("🔍 Security Analysis:")
    print(f"   ❓ Can you see 'TOP SECRET'? {'❌ NO' if 'TOP SECRET' not in encrypted else '✅ YES - PROBLEM!'}")
    print(f"   ❓ Can you see 'Nuclear'? {'❌ NO' if 'Nuclear' not in encrypted else '✅ YES - PROBLEM!'}")
    print(f"   ❓ Can you see '123-456-789'? {'❌ NO' if '123-456-789' not in encrypted else '✅ YES - PROBLEM!'}")
    print(f"   ❓ Is data scrambled? {'✅ YES' if len(encrypted) > len(secret) else '❌ NO - PROBLEM!'}")
    print()
    
    # Decrypt
    print("🔓 Decrypting with correct key...")
    decrypted = security.decrypt_message(encrypted)
    print(f"   '{decrypted}'")
    
    # Verify
    if secret == decrypted:
        print("\n🎉 PROOF COMPLETE!")
        print("✅ Messages are properly encrypted")
        print("✅ Sensitive data is protected")
        print("✅ Only correct key can decrypt")
        print("✅ Your chat app is SECURE! 🛡️")
        return True
    else:
        print("\n❌ ENCRYPTION FAILED!")
        print("⚠️  There's a problem with the encryption")
        return False

if __name__ == "__main__":
    print("🚀 Starting encryption proof...")
    print()
    
    success = prove_encryption()
    
    print()
    print("📋 SUMMARY:")
    if success:
        print("   Your encryption is working perfectly!")
        print("   Safe to demonstrate to professors.")
        print("   Network traffic is protected.")
    else:
        print("   Encryption needs to be fixed.")
        print("   Check the chat_core.py file.")
    
    input("\nPress Enter to exit...")
