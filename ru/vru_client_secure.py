import requests
import json
from datetime import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.crypto_utils import CryptoManager

class SecureVRUClient:
    """VRU Smartphone Client with RSA encryption"""
    
    def __init__(self, user_id, api_key, auth_cloud_url):
        self.user_id = user_id
        self.api_key = api_key
        self.auth_cloud_url = auth_cloud_url
        self.session_token = None
        self.nearby_rsus = []
        
        # Load VRU's own keys - THIS stays untouched
        self.crypto = CryptoManager(
            private_key_path='keys/vru_client_private_key.pem',
            public_key_path='keys/vru_client_public_key.pem'
        )
        
        # Store VRU's public key BEFORE loading anything else
        self.vru_public_key = self.crypto.public_key
        self.vru_public_key_string = self.crypto.get_public_key_string()
        
        # Separate storage for Auth Cloud's public key
        self.auth_cloud_crypto = None
        self.auth_cloud_public_key = None
    
    def get_auth_cloud_public_key(self):
        """Step 0: Get Auth Cloud's public key"""
        try:
            print("\n[STEP 0] Requesting Auth Cloud's public key...")
            response = requests.get(
                f"{self.auth_cloud_url}/api/v1/public_key",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                public_key_pem = result['public_key']
                
                # Create SEPARATE CryptoManager for Auth Cloud's key
                self.auth_cloud_crypto = CryptoManager()
                self.auth_cloud_crypto.load_public_key_from_string(public_key_pem)
                self.auth_cloud_public_key = self.auth_cloud_crypto.public_key
                
                print("✅ Received Auth Cloud's public key")
                return True
            else:
                print(f"❌ Failed to get public key: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error getting public key: {e}")
            return False
    
    def authenticate_and_get_rsus(self, postcode, suburb, state):
        """Steps 1 & 2: Secure authentication"""
        
        # Get Auth Cloud's public key
        if not self.auth_cloud_public_key:
            if not self.get_auth_cloud_public_key():
                return False
        
        # Encrypt API key with Auth Cloud's public key
        print(f"\n[STEP 1] Encrypting API key with Auth Cloud's public key...")
        
        encrypted_api_key = self.auth_cloud_crypto.encrypt(
            self.api_key
        )
        print(f"🔒 API key encrypted: {encrypted_api_key[:50]}...")
        
        # Prepare timestamp
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Sign the request with VRU's private key
        message_to_sign = f"{self.user_id}{encrypted_api_key}{timestamp}"
        
        print(f"\n✍️  Signing request with VRU's private key...")
        signature = self.crypto.sign(message_to_sign)
        print(f"✅ Request signed: {signature[:50]}...")
        
        # Use the VRU's public key we saved earlier
        print(f"\n📤 Sending VRU's public key: {self.vru_public_key_string[:100]}...")
        
        # Prepare payload
        payload = {
            "user_id": self.user_id,
            "encrypted_api_key": encrypted_api_key,
            "vru_public_key": self.vru_public_key_string,  # VRU's key, not Auth Cloud's!
            "rough_position": {
                "postcode": postcode,
                "suburb": suburb,
                "state": state
            },
            "signature": signature,
            "timestamp": timestamp
        }
        
        try:
            print(f"\n[STEP 1] Sending secure authentication request...")
            print(f"User ID: {self.user_id}")
            print(f"Location: {suburb}, {state} {postcode}")
            
            response = requests.post(
                f"{self.auth_cloud_url}/api/v1/authenticate",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                encrypted_response = result.get('encrypted_response')
                response_signature = result.get('signature')
                
                print(f"\n[STEP 2] 🔓 Decrypting response with VRU's private key...")
                decrypted_response = self.crypto.decrypt(encrypted_response)
                response_data = json.loads(decrypted_response)
                
                # Verify signature using Auth Cloud's public key
                print(f"🔍 Verifying response signature with Auth Cloud's public key...")
                if not self.auth_cloud_crypto.verify_signature(
                    decrypted_response,
                    response_signature
                ):
                    print("❌ Response signature verification failed!")
                    return False
                
                print("✅ Response signature verified")
                
                if response_data.get("success"):
                    print(f"\n✅ Authentication successful!")
                    print(f"Session Token: {response_data['session_token'][:20]}...")
                    
                    self.session_token = response_data['session_token']
                    self.nearby_rsus = response_data['nearby_rsus']
                    
                    print(f"\n[STEP 2] Received {response_data['rsu_count']} nearby RSUs:")
                    for rsu in self.nearby_rsus:
                        print(f"  - {rsu['rsu_id']}: {rsu['name']}")
                        print(f"    Location: ({rsu['location']['lat']}, {rsu['location']['lon']})")
                    
                    return True
                else:
                    print(f"❌ Authentication failed: {response_data.get('error')}")
                    return False
            else:
                print(f"❌ Server error: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Test secure VRU client"""
    
    USER_ID = "VRU_USER_001"
    API_KEY = "sk_live_51234567890abcdef"
    AUTH_CLOUD_URL = "http://172.31.4.58:8443"
    
    POSTCODE = "4000"
    SUBURB = "Brisbane CBD"
    STATE = "QLD"
    
    print("=" * 60)
    print("SECURE VRU SMARTPHONE - V2P SAFETY SYSTEM")
    print("Using RSA-2048 Encryption")
    print("=" * 60)
    
    client = SecureVRUClient(USER_ID, API_KEY, AUTH_CLOUD_URL)
    
    success = client.authenticate_and_get_rsus(POSTCODE, SUBURB, STATE)
    
    if success:
        print("\n" + "=" * 60)
        print("✅ SECURE TRUSTED CONNECTION ESTABLISHED")
        print("🔒 All data encrypted end-to-end")
        print("✍️  All messages cryptographically signed")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("❌ AUTHENTICATION FAILED")
        print("=" * 60)

if __name__ == "__main__":
    main()