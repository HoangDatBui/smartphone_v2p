from flask import Flask, request, jsonify
import secrets
from datetime import datetime, timedelta
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.crypto_utils import CryptoManager
from shared.database import get_db
import json

app = Flask(__name__)

# Initialize crypto manager with Auth Cloud's keys
crypto = CryptoManager(
    private_key_path='../keys/auth_cloud_private_key.pem',
    public_key_path='../keys/auth_cloud_public_key.pem'
)

# Initialize database connection (for user authentication)
db = get_db()

# RSU database (hardcoded for now)
RSU_DATABASE = {
    "4000": [
        {
            "rsu_id": "RSU_BNE_001",
            "name": "Queen St & Adelaide St",
            "location": {"lat": -27.4698, "lon": 153.0251},
            "ip": "3.25.61.202",
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
        
        print(f"[AUTH] Request from {user_id} ({rough_position.get('suburb')}, {postcode})")
        
        # Create a separate CryptoManager for the VRU
        try:
            vru_crypto = CryptoManager()
            vru_crypto.load_public_key_from_string(vru_public_key_pem)
        except Exception as e:
            print(f"[AUTH] ❌ Invalid VRU public key: {e}")
            return jsonify({
                "success": False,
                "error": "Invalid VRU public key"
            }), 400
        
        # Verify signature
        message_to_verify = f"{user_id}{encrypted_api_key}{timestamp}"
        
        try:
            is_valid = vru_crypto.verify_signature(message_to_verify, signature)
        except Exception as e:
            print(f"[AUTH] ❌ Signature verification error: {e}")
            return jsonify({
                "success": False,
                "error": f"Signature verification error: {str(e)}"
            }), 401
        
        if not is_valid:
            print(f"[AUTH] ❌ Invalid signature from {user_id}")
            return jsonify({
                "success": False,
                "error": "Invalid signature"
            }), 401
        
        # Validate timestamp (prevent replay attacks - request must be within 20 minutes)
        try:
            request_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            current_time = datetime.utcnow().replace(tzinfo=request_time.tzinfo)
            time_diff = (current_time - request_time).total_seconds() / 60  # Convert to minutes
            
            if time_diff > 20:
                print(f"[AUTH] ❌ Request expired from {user_id}")
                return jsonify({
                    "success": False,
                    "error": "Request expired (must be within 20 minutes)"
                }), 401
            
            if time_diff < 0:
                # Allow small clock skew (up to 5 minutes)
                if abs(time_diff) > 5:
                    return jsonify({
                        "success": False,
                        "error": "Invalid timestamp (clock skew too large)"
                    }), 401
        except Exception as e:
            print(f"[AUTH] ❌ Invalid timestamp from {user_id}: {e}")
            return jsonify({
                "success": False,
                "error": "Invalid timestamp format"
            }), 400
        
        # Decrypt API key
        try:
            decrypted_api_key = crypto.decrypt(encrypted_api_key)
        except Exception as e:
            print(f"[AUTH] ❌ Decryption failed for {user_id}: {e}")
            return jsonify({
                "success": False,
                "error": "Decryption failed"
            }), 401
        
        # Validate decrypted API key using database
        if not db.verify_api_key(user_id, decrypted_api_key):
            print(f"[AUTH] ❌ Invalid credentials for {user_id}")
            return jsonify({
                "success": False,
                "error": "Invalid credentials"
            }), 401
        
        # Find nearby RSUs (hardcoded)
        nearby_rsus = RSU_DATABASE.get(postcode, [])
        
        # Generate temporary certificate for RSU authentication (valid for 20 minutes)
        temporary_cert = secrets.token_urlsafe(32)
        cert_expires_at = datetime.utcnow() + timedelta(minutes=20)
        
        # Prepare response
        response_data = {
            "success": True,
            "user_id": user_id,
            "temporary_cert": temporary_cert,
            "cert_expires_at": cert_expires_at.isoformat() + "Z",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "rough_position": rough_position,
            "nearby_rsus": nearby_rsus,
            "rsu_count": len(nearby_rsus)
        }
        
        response_json = json.dumps(response_data)
        
        # Encrypt response
        encrypted_response = crypto.encrypt(response_json, vru_crypto.public_key)
        
        # Sign response
        response_signature = crypto.sign(response_json)
        
        print(f"[AUTH] ✅ Authenticated {user_id}, returning {len(nearby_rsus)} RSU(s)")
        
        return jsonify({
            "encrypted_response": encrypted_response,
            "signature": response_signature
        }), 200
        
    except Exception as e:
        print(f"[AUTH] ❌ Error: {e}")
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
    print("Using RSA-2048 encryption + PostgreSQL")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8443, debug=True)