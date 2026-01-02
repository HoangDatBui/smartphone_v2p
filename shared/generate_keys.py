"""
Generate RSA key pairs for both Auth Cloud and VRU Client
Run this once to create the keys
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

def generate_key_pair(name):
    """Generate RSA-2048 key pair and save to files"""
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Serialize private key (PEM format, encrypted)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # For demo; use password in production
    )
    
    # Serialize public key (PEM format)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Create keys directory if it doesn't exist
    os.makedirs('keys', exist_ok=True)
    
    # Save private key
    with open(f'keys/{name}_private_key.pem', 'wb') as f:
        f.write(private_pem)
    
    # Save public key
    with open(f'keys/{name}_public_key.pem', 'wb') as f:
        f.write(public_pem)
    
    print(f"✅ Generated key pair for {name}")
    print(f"   Private key: keys/{name}_private_key.pem")
    print(f"   Public key:  keys/{name}_public_key.pem")

def main():
    print("=" * 60)
    print("RSA KEY PAIR GENERATION")
    print("=" * 60)
    
    # Generate keys for Auth Cloud
    print("\n[1/2] Generating Auth Cloud keys...")
    generate_key_pair('auth_cloud')
    
    # Generate keys for VRU Client
    print("\n[2/2] Generating VRU Client keys...")
    generate_key_pair('vru_client')
    
    print("\n" + "=" * 60)
    print("✅ KEY GENERATION COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Copy auth_cloud keys to Auth Cloud instance")
    print("2. Copy vru_client keys to VRU/RSU instance")
    print("3. Exchange public keys between systems")
    print("=" * 60)

if __name__ == "__main__":
    main()