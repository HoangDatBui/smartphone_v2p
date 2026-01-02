from flask import Flask, request, jsonify
import secrets
from datetime import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.crypto_utils import CryptoManager
import json
import traceback

app = Flask(__name__)

# Initialize crypto manager with Auth Cloud's keys
crypto = CryptoManager(
    private_key_path='../keys/auth_cloud_private_key.pem',
    public_key_path='../keys/auth_cloud_public_key.pem'
)

# Store VRU public keys
VRU_PUBLIC_KEYS = {}

# Valid users database
VALID_USERS = {
    "VRU_USER_001": {
        "api_key": "sk_live_51234567890abcdef",
        "active": True
    }
}

# RSU database
RSU_DATABASE = {
    "4000": [
        {
            "rsu_id": "RSU_BNE_001",
            "name": "Queen St & Adelaide St",
            "location": {"lat": -27.4698, "lon": 153.0251},
            "ip": "203.123.45.10",
            "port": 5000
        },
        {
            "rsu_id": "RSU_BNE_002", 
            "name": "George St & Elizabeth St",
            "location": {"lat": -27.4705, "lon": 153.0235},
            "ip": "203.123.45.11",
            "port": 5000
        }
    ],
    "4006": [
        {
            "rsu_id": "RSU_FV_001",
            "name": "Brunswick St & Ann St",
            "location": {"lat": -27.4579, "lon": 153.0346},
            "ip": "203.123.45.20",
            "port": 5000
        }
    ]
}

@app.route('/api/v1/public_key', methods=['GET'])
def get_public_key():
    """Step 0: VRU Client requests Auth Cloud's public key"""
    return jsonify({
        "success": True,
        "public_key": crypto.get_public_key_string(),
        "key_type": "RSA-2048",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200

@app.route('/api/v1/authenticate', methods=['POST'])
def authenticate_secure():
    """Step 1 & 2: Secure authentication with encrypted API key"""
    try:
        data = request.get_json()
        
        user_id = data.get('user_id')
        encrypted_api_key = data.get('encrypted_api_key')
        vru_public_key_pem = data.get('vru_public_key')
        rough_position = data.get('rough_position', {})
        signature = data.get('signature')
        timestamp = data.get('timestamp')
        postcode = rough_position.get('postcode')
        
        # Validate required fields
        if not all([user_id, encrypted_api_key, vru_public_key_pem, postcode, signature]):
            missing = []
            if not user_id: missing.append("user_id")
            if not encrypted_api_key: missing.append("encrypted_api_key")
            if not vru_public_key_pem: missing.append("vru_public_key")
            if not postcode: missing.append("postcode")
            if not signature: missing.append("signature")
            
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing)}"
            }), 400
        
        print(f"\n[STEP 1] Authentication request from {user_id}")
        print(f"Location: {rough_position.get('suburb')}, {postcode}")
        
        # Create a separate CryptoManager for the VRU
        print(f"\nLoading VRU's public key...")
        print(f"Public key preview: {vru_public_key_pem[:100]}...")
        
        try:
            vru_crypto = CryptoManager()
            vru_crypto.load_public_key_from_string(vru_public_key_pem)
            print(f"✅ VRU public key loaded successfully")
        except Exception as e:
            print(f"❌ Failed to load VRU public key: {e}")
            traceback.print_exc()
            return jsonify({
                "success": False,
                "error": "Invalid VRU public key"
            }), 400
        
        # Verify signature
        message_to_verify = f"{user_id}{encrypted_api_key}{timestamp}"
        
        print(f"\n🔍 Signature Verification Debug:")
        print(f"  User ID: {user_id}")
        print(f"  Encrypted API key (first 50 chars): {encrypted_api_key[:50]}...")
        print(f"  Timestamp: {timestamp}")
        print(f"  Message length: {len(message_to_verify)} chars")
        print(f"  Signature (first 50 chars): {signature[:50]}...")
        print(f"  Signature length: {len(signature)} chars")
        
        try:
            is_valid = vru_crypto.verify_signature(message_to_verify, signature)
            print(f"  Verification result: {is_valid}")
        except Exception as e:
            print(f"❌ Signature verification threw exception: {e}")
            traceback.print_exc()
            return jsonify({
                "success": False,
                "error": f"Signature verification error: {str(e)}"
            }), 401
        
        if not is_valid:
            print("❌ Signature verification failed!")
            return jsonify({
                "success": False,
                "error": "Invalid signature"
            }), 401
        
        print("✅ Signature verified - request is authentic")
        
        # Decrypt API key
        try:
            print(f"\n🔓 Decrypting API key...")
            decrypted_api_key = crypto.decrypt(encrypted_api_key)
            print(f"✅ Decrypted API key: {decrypted_api_key[:10]}...")
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            traceback.print_exc()
            return jsonify({
                "success": False,
                "error": "Decryption failed"
            }), 401
        
        # Validate decrypted API key
        if user_id not in VALID_USERS:
            print(f"❌ Unknown user: {user_id}")
            return jsonify({
                "success": False,
                "error": "Unknown user"
            }), 401
        
        if not VALID_USERS[user_id]["active"]:
            print(f"❌ User inactive: {user_id}")
            return jsonify({
                "success": False,
                "error": "Account inactive"
            }), 401
        
        expected_key = VALID_USERS[user_id]["api_key"]
        if not secrets.compare_digest(decrypted_api_key, expected_key):
            print(f"❌ API key mismatch!")
            print(f"   Expected: {expected_key[:20]}...")
            print(f"   Got:      {decrypted_api_key[:20]}...")
            return jsonify({
                "success": False,
                "error": "Invalid API key"
            }), 401
        
        print("✅ API key validated - user authenticated")
        
        # Find nearby RSUs
        nearby_rsus = RSU_DATABASE.get(postcode, [])
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        
        # Prepare response
        response_data = {
            "success": True,
            "user_id": user_id,
            "session_token": session_token,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "rough_position": rough_position,
            "nearby_rsus": nearby_rsus,
            "rsu_count": len(nearby_rsus)
        }
        
        response_json = json.dumps(response_data)
        
        # Encrypt response
        print(f"\n🔒 Encrypting response for VRU...")
        encrypted_response = crypto.encrypt(response_json, vru_crypto.public_key)
        
        # Sign response
        print(f"✍️  Signing response...")
        response_signature = crypto.sign(response_json)
        
        print(f"\n[STEP 2] ✅ Returning {len(nearby_rsus)} nearby RSUs")
        
        return jsonify({
            "encrypted_response": encrypted_response,
            "signature": response_signature
        }), 200
        
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/v1/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "service": "Authentication Cloud (Secure)",
        "encryption": "RSA-2048",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200

if __name__ == '__main__':
    print("=" * 60)
    print("SECURE AUTHENTICATION CLOUD SERVER")
    print("Using RSA-2048 encryption")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8443, debug=True)