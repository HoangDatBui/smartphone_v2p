"""
Cryptographic utilities for secure communication
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

class CryptoManager:
    """Handle all encryption/decryption operations"""
    
    def __init__(self, private_key_path=None, public_key_path=None):
        self.private_key = None
        self.public_key = None
        
        if private_key_path:
            self.load_private_key(private_key_path)
        
        if public_key_path:
            self.load_public_key(public_key_path)
    
    def load_private_key(self, path):
        """Load private key from PEM file"""
        with open(path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        print(f"✅ Loaded private key from {path}")
    
    def load_public_key(self, path):
        """Load public key from PEM file"""
        with open(path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        print(f"✅ Loaded public key from {path}")
    
    def load_public_key_from_string(self, public_key_pem):
        """Load public key from PEM string"""
        self.public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
    
    def get_public_key_string(self):
        """Export public key as PEM string"""
        if not self.public_key:
            self.public_key = self.private_key.public_key()
        
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def encrypt(self, message, recipient_public_key=None):
        """
        Encrypt message using recipient's public key
        Uses HYBRID encryption for large messages (RSA + AES)
        """
        public_key = recipient_public_key or self.public_key
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Generate random AES key (32 bytes = AES-256)
        aes_key = os.urandom(32)
        
        # Generate random IV (16 bytes for AES)
        iv = os.urandom(16)
        
        # Encrypt message with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad message to AES block size (16 bytes)
        padding_length = 16 - (len(message) % 16)
        padded_message = message + bytes([padding_length]) * padding_length
        
        aes_encrypted = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine: encrypted_key + iv + encrypted_data
        combined = encrypted_aes_key + iv + aes_encrypted
        
        # Return base64-encoded for JSON transport
        return base64.b64encode(combined).decode('utf-8')
    
    def decrypt(self, encrypted_message_b64):
        """
        Decrypt message using own private key
        Handles HYBRID encryption (RSA + AES)
        """
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        # Decode from base64
        combined = base64.b64decode(encrypted_message_b64)
        
        # Split components
        # RSA-2048 encrypted key is 256 bytes
        encrypted_aes_key = combined[:256]
        iv = combined[256:272]  # 16 bytes
        aes_encrypted = combined[272:]
        
        # Decrypt AES key with RSA
        aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_message = decryptor.update(aes_encrypted) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_message[-1]
        message = padded_message[:-padding_length]
        
        return message.decode('utf-8')
    
    def sign(self, message):
        """
        Sign message with private key (proves authenticity)
        Anyone with public key can verify
        """
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message, signature_b64, signer_public_key=None):
        """
        Verify message signature (proves sender authenticity)
        """
        public_key = signer_public_key or self.public_key
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = base64.b64decode(signature_b64)
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

def test_crypto():
    """Test encryption/decryption"""
    print("\n" + "=" * 60)
    print("TESTING HYBRID ENCRYPTION")
    print("=" * 60)
    
    # Simulate two parties
    alice = CryptoManager('../keys/auth_cloud_private_key.pem', '../keys/auth_cloud_public_key.pem')
    bob = CryptoManager('../keys/vru_client_private_key.pem', '../keys/vru_client_public_key.pem')
    
    # Test with LARGE message (bigger than RSA can handle)
    large_message = "sk_live_51234567890abcdef" * 100  # 2600 chars
    print(f"\n📤 Bob encrypts large message ({len(large_message)} chars)")
    encrypted = bob.encrypt(large_message, alice.public_key)
    print(f"🔒 Encrypted: {encrypted[:50]}...")
    
    # Alice decrypts
    decrypted = alice.decrypt(encrypted)
    print(f"🔓 Alice decrypts: {decrypted[:50]}... ({len(decrypted)} chars)")
    
    # Verify
    if large_message == decrypted:
        print("✅ SUCCESS: Hybrid Encryption working!")
    else:
        print("❌ FAILED: Messages don't match")
    
    # Test signing
    print("\n" + "=" * 60)
    print("TESTING DIGITAL SIGNATURE")
    print("=" * 60)
    
    message = "VRU_USER_001"
    signature = bob.sign(message)
    print(f"\n✍️  Bob signs: '{message}'")
    
    is_valid = alice.verify_signature(message, signature, bob.public_key)
    print(f"✅ Alice verifies: {is_valid}")

if __name__ == "__main__":
    test_crypto()