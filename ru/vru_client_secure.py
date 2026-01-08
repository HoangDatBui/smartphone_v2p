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
        self.temporary_cert = None
        self.nearby_rsus = []
        
        # Load VRU's own keys - THIS stays untouched
        self.crypto = CryptoManager(
            private_key_path='../keys/vru_client_private_key.pem',
            public_key_path='../keys/vru_client_public_key.pem'
        )
        
        # Store VRU's public key BEFORE loading anything else
        self.vru_public_key = self.crypto.public_key
        self.vru_public_key_string = self.crypto.get_public_key_string()
        
        # Separate storage for Auth Cloud's public key
        self.auth_cloud_crypto = None
        self.auth_cloud_public_key = None
        
        # RSU connection storage
        self.rsu_crypto = None
        self.rsu_public_key = None
    
    def get_auth_cloud_public_key(self):
        """Step 0: Get Auth Cloud's public key"""
        try:
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
        encrypted_api_key = self.auth_cloud_crypto.encrypt(self.api_key)
        
        # Prepare timestamp
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Sign the request with VRU's private key
        message_to_sign = f"{self.user_id}{encrypted_api_key}{timestamp}"
        signature = self.crypto.sign(message_to_sign)
        
        print(f"[STEP 1] 🔒 API key encrypted & ✍️ request signed")
        print(f"[STEP 1] Sending authentication: {self.user_id} @ {suburb}, {state} {postcode}")
        
        # Prepare payload
        payload = {
            "user_id": self.user_id,
            "encrypted_api_key": encrypted_api_key,
            "vru_public_key": self.vru_public_key_string,
            "rough_position": {
                "postcode": postcode,
                "suburb": suburb,
                "state": state
            },
            "signature": signature,
            "timestamp": timestamp
        }
        
        try:
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
                
                decrypted_response = self.crypto.decrypt(encrypted_response)
                response_data = json.loads(decrypted_response)
                
                # Verify signature using Auth Cloud's public key
                if not self.auth_cloud_crypto.verify_signature(
                    decrypted_response,
                    response_signature
                ):
                    print("❌ Response signature verification failed!")
                    return False
                
                print(f"[STEP 2] 🔓 Response decrypted & ✅ signature verified")
                
                if response_data.get("success"):
                    self.temporary_cert = response_data['temporary_cert']
                    self.nearby_rsus = response_data['nearby_rsus']
                    
                    # Format RSU list concisely
                    rsu_list = ", ".join([f"{rsu['rsu_id']} ({rsu['name']})" for rsu in self.nearby_rsus])
                    
                    print(f"✅ Authentication successful! Temporary certificate received.")
                    print(f"   Nearby RSUs: {rsu_list}")
                    
                    return True
                else:
                    print(f"❌ Authentication failed: {response_data.get('error')}")
                    return False
            else:
                print(f"❌ Server error: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_rsu_public_key(self, rsu_url, rsu_id=None):
        """Step 3a: Get RSU's public key"""
        try:
            response = requests.get(
                f"{rsu_url}/api/v1/public_key",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                public_key_pem = result['public_key']
                
                # Create SEPARATE CryptoManager for RSU's key
                self.rsu_crypto = CryptoManager()
                self.rsu_crypto.load_public_key_from_string(public_key_pem)
                self.rsu_public_key = self.rsu_crypto.public_key
                
                rsu_name = result.get('rsu_id', rsu_id or 'RSU')
                print(f"[STEP 3] 📡 Connecting to {rsu_name}...")
                return True
            else:
                print(f"❌ Failed to get RSU public key: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error getting RSU public key: {e}")
            return False
    
    def send_precise_position_to_rsu(self, rsu_url, precise_position, rsu_id=None):
        """
        Step 3: Send precise position to RSU using temporary certificate
        
        This is ONE-WAY communication (VRU -> RSU only, no response expected)
        
        Args:
            rsu_url: URL of the RSU server (e.g., "http://203.123.45.10:5000")
            precise_position: Dict with lat, lon, speed
            rsu_id: Optional RSU ID for display purposes
        
        Returns:
            bool: True if position sent successfully (HTTP 200)
        """
        # Ensure we have temporary certificate
        if not self.temporary_cert:
            print("❌ No temporary certificate. Run authentication first.")
            return False
        
        # Get RSU's public key if not already obtained
        if not self.rsu_public_key:
            if not self.get_rsu_public_key(rsu_url, rsu_id):
                return False
        
        # Prepare position data payload
        position_data = {
            "user_id": self.user_id,
            "precise_position": precise_position
        }
        
        position_json = json.dumps(position_data)
        
        # Encrypt position data with RSU's public key
        encrypted_data = self.rsu_crypto.encrypt(position_json)
        
        # Prepare timestamp
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Sign the request with VRU's private key
        message_to_sign = f"{encrypted_data}{self.temporary_cert}{timestamp}"
        signature = self.crypto.sign(message_to_sign)
        
        print(f"[STEP 3] 🔒 Position encrypted & ✍️ request signed")
        print(f"📍 Position: ({precise_position.get('lat')}, {precise_position.get('lon')}) | Speed: {precise_position.get('speed', 'N/A')} m/s")
        
        # Prepare payload
        payload = {
            "encrypted_data": encrypted_data,
            "temporary_cert": self.temporary_cert,
            "vru_public_key": self.vru_public_key_string,
            "signature": signature,
            "timestamp": timestamp
        }
        
        try:
            response = requests.post(
                f"{rsu_url}/api/v1/register_position",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            # One-way communication - just check HTTP status
            if response.status_code == 200:
                print(f"✅ Position sent to RSU (one-way communication)")
                return True
            else:
                print(f"❌ RSU rejected the request: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending to RSU: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Test secure VRU client - Full workflow Steps 1-3"""
    
    USER_ID = "VRU_USER_001"
    API_KEY = "sk_live_51234567890abcdef"
    AUTH_CLOUD_URL = "http://127.0.0.1:8443"
    
    # Step 1 & 2: Rough position for authentication
    POSTCODE = "4000"
    SUBURB = "Brisbane CBD"
    STATE = "QLD"
    
    # Step 3: Precise position (hard-coded for now)
    PRECISE_POSITION = {
        "lat": -27.4695,
        "lon": 153.0253,
        "speed": 1.2            # Speed in m/s (walking pace)
    }
    
    # RSU URL - using first RSU from the list or direct connection
    RSU_URL = "http://127.0.0.1:5000"
    
    print("=" * 60)
    print("SECURE VRU SMARTPHONE - V2P SAFETY SYSTEM")
    print("=" * 60 + "\n")
    
    client = SecureVRUClient(USER_ID, API_KEY, AUTH_CLOUD_URL)
    
    # Steps 1 & 2: Authentication and RSU discovery
    success = client.authenticate_and_get_rsus(POSTCODE, SUBURB, STATE)
    
    if success:
        # Step 3: Send precise position to RSU
        rsu_url = RSU_URL
        rsu_id = None
        if client.nearby_rsus:
            first_rsu = client.nearby_rsus[0]
            rsu_id = first_rsu['rsu_id']
        
        print()  # Blank line before Step 3
        position_success = client.send_precise_position_to_rsu(rsu_url, PRECISE_POSITION, rsu_id)
        
        if position_success:
            print("\n" + "=" * 60)
            print("✅ ALL STEPS COMPLETE - VRU registered with intersection")
            print("=" * 60)
        else:
            print("\n" + "=" * 60)
            print("❌ STEP 3 FAILED - RSU Connection Error")
            print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("❌ AUTHENTICATION FAILED")
        print("=" * 60)

if __name__ == "__main__":
    main()